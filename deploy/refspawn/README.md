# refspawn — isolated compartments for spawned child runs

`refspawn` serves Agenthof's spawn door. When an agent asks Agenthof to run
a child workflow (`POST /spawn`), Agenthof asks refspawn — over a Unix
socket only Agenthof dials — for an isolated set to run that child in.
refspawn creates one named podman volume for the child, starts one
rootless-podman refbox compartment per agent in the child's workflow (all
mounting that volume at `/work`, no network, reaching Agenthof only over
the child's own socket directory), starts one `refexec` host process bound
to the same volume for the child's first-hand exec, waits until every
socket answers, and hands the paths back. Agenthof then runs the child as a
full governed run against those sockets. When the child is over — or when
anything in the set dies, or Agenthof's request ends — refspawn tears the
set down in order and removes the volume.

refspawn is a **host process**, like `agenthof` and `refexec` — it invokes
`podman` itself. It is credential-less.

## Config (every key is required; nothing is defaulted)

See [`spawn-config/refspawn.yaml`](spawn-config/refspawn.yaml), the
annotated reference. `refspawn -config refspawn.yaml -check` validates it
and prints `socket=<path>` and `spawn_root=<dir>` without listening.

The socket's directory is the access gate: it must be mode 0700 and owned
by the user refspawn runs as, and it must not be under Agenthof's
`refbox_socket_dir` (mounted into agent compartments) nor under
`spawn_root` (whose child directories are). Agenthof checks the same before
it dials.

`images` maps each agent name to the image its compartment runs. A child
workflow that names an agent not listed is refused before anything starts,
and Agenthof records the refusal. Pull the images yourself: refspawn runs
podman with `--pull=never`.

## What one child gets

- A named volume `agenthof-spawn-<run id>-work`, created when the child is
  provisioned and removed when it is torn down. Nothing else mounts it.
- One compartment per distinct agent in the child's workflow, named
  `agenthof-spawn-<run id>-<agent>`: `--network none`, a read-only root,
  every capability dropped, `no-new-privileges`, the host user's id, the
  memory / CPU / pid caps, `--timeout` as a backstop, `--pull=never`, and
  exactly two mounts — the child's volume read-write at `/work`, and the
  child's socket directory `<spawn_root>/<run id>` at its own path. The
  agent listens on `<spawn_root>/<run id>/<agent>.sock`; the child's
  per-step gateway listens in the same directory.
- One `refexec` process on the host, configured from the `refexec` template
  plus the child's volume, listening on
  `<spawn_root>/<run id>-exec/refexec.sock`. That directory is never
  mounted into any compartment: a child's agent reaches its refexec only
  through Agenthof's exec door.

Agents of one child share the child's `/work` on purpose: a workflow's
steps run one at a time and pass work along it. Two children — siblings
spawned in parallel, or a parent and its child — never share a volume.

## The request

`POST /provision` with `{"child_run_id": "...", "agents": ["a", "b"]}`.
refspawn reserves the slots (`max_compartments` counts agent compartments
across every live child; a set that will not fit is refused whole), starts
the set, and answers `200` with one JSON line
`{"child_dir", "agent_sockets", "exec_socket"}` once every socket accepts a
connection. The response body then stays open for as long as the set
lives. Agenthof closing it is the teardown request; the body ending on
refspawn's side means the set is gone.

Any other status is a refusal Agenthof records as
`spawn compartment unavailable`: a malformed request, an agent with no
image, the cap, a child that already has a live set, a start that failed,
or sockets that never answered within `ready_timeout`.

## Teardown, in order

1. `SIGTERM` to the child's refexec, which removes any exec compartment it
   still holds and exits.
2. `podman rm -f` each agent compartment.
3. `podman volume rm` the child's volume — possible only once nothing
   mounts it, which is why the order matters.
4. The child's two directories.

At start-up, and again at shutdown, refspawn removes every container and
volume whose name carries `agenthof-spawn-` and every directory under
`spawn_root`: what a previous refspawn left behind when it died with
children in flight.

## Run it locally (Linux host with rootless podman)

```
go build -o /tmp/refexec ./deploy/refexec
go build -o /tmp/refspawn ./deploy/refspawn
podman build -f deploy/refbox/Containerfile -t localhost/refbox-echo:test .
podman pull docker.io/library/busybox:1.36.1
mkdir -p -m 0700 "$XDG_RUNTIME_DIR/agenthof-spawn"
sed "s|/run/agenthof-spawn|$XDG_RUNTIME_DIR/agenthof-spawn|; s|command: \[refexec\]|command: [/tmp/refexec]|" deploy/refspawn/spawn-config/refspawn.yaml >/tmp/refspawn.yaml
/tmp/refspawn -config /tmp/refspawn.yaml
```

Then set `spawn_supervisor: unix://$XDG_RUNTIME_DIR/agenthof-spawn/refspawn.sock`
(written out as the absolute path) in Agenthof's `gateway.yaml`, and
`may_spawn` on the agent that may spawn. `scripts/e2e-spawn.sh` runs this
whole path with real podman; `scripts/e2e-spawn-local.sh` runs the same
door and ledger proof on any machine, against a stand-in whose compartments
are host processes.

## Limits, stated

- A child's agents run offline, like any refbox compartment.
- refspawn is a trusted host process running as the operator's user and
  invoking podman. Its socket directory's permissions and the mount
  namespace are the gate on who may ask.
- If `agenthof` is killed outright, its held requests close and refspawn
  tears the children down. If refspawn itself is killed outright, the
  children live until podman's `--timeout` trips, or until the next
  refspawn starts and reaps them by name.
- `max_compartments` counts agent compartments; each child's refexec is a
  host process whose transient exec compartments are bounded by its own
  `max_compartments`, not by this one.
- A child always gets a fresh, empty volume. Handing a child a shared or
  persistent workspace is not supported.
