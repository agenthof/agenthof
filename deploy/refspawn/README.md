# refspawn — separate compartments for spawned child runs

`refspawn` serves Agenthof's spawn door. When an agent asks Agenthof to
run a child workflow (`POST /spawn`), Agenthof asks refspawn — over a Unix
socket only Agenthof dials — for a separate set to run that child in.
refspawn creates one workspace for the child, starts one confined
compartment per agent in the child's workflow (all sharing that workspace,
direct network access denied, reaching Agenthof only over the child's own
socket directory), starts one `refexec` host process bound to the same
workspace for the child's first-hand exec, waits until every socket
answers, and hands the paths back. Agenthof then runs the child as a full
governed run against those sockets. When the child is over — or when
anything in the set dies, or Agenthof's request ends — refspawn tears the
set down in order and removes the workspace.

The compartments are made by a **confinement backend** the config selects,
the same one [`refexec`](../refexec/README.md#backends) uses: rootless
podman on Linux (a refbox container per agent, the workspace a named
volume), or macOS Seatbelt (a sandboxed host process per agent, the
workspace a directory under `store_root`). The tiers have different limits;
see [Backends](#backends).

refspawn is a **host process**, like `agenthof` and `refexec` — it drives
the backend itself. It is credential-less.

## Config (every key is required; nothing is defaulted)

See [`spawn-config/refspawn.yaml`](spawn-config/refspawn.yaml), the
annotated reference (a podman config). `refspawn -config refspawn.yaml
-check` validates it and prints `socket=<path>` and `spawn_root=<dir>`
without listening.

`confiner:` selects the backend (`podman`, or `seatbelt`; omit it for the
host's default — podman on Linux, Seatbelt on macOS). The backend keys
differ, and a key the selected backend does not consume is refused rather
than ignored:

- **podman:** `refexec.image` (the image each child's exec compartments
  run); each `images` value is an image reference.
- **seatbelt:** `store_root` and `pid_dir` (absolute directories that
  must already exist), optionally `deny_read` (extra subtrees compartments
  may not read) and `shared_host_scratch`; no `refexec.image`. Each
  `images` value is the absolute path of the executable that runs as that
  agent. `limits` and `refexec.limits` are required by the schema but not
  enforced on this tier.

```yaml
confiner: seatbelt
socket: /usr/local/var/agenthof/spawn/refspawn.sock
spawn_root: /usr/local/var/agenthof/spawn/children
store_root: /usr/local/var/agenthof/stores
pid_dir: /usr/local/var/agenthof/pids
images:
  my-agent: /usr/local/bin/my-agent       # an absolute executable path, not an image
timeout: 10m
ready_timeout: 60s
limits: {memory: 256m, cpus: "1", pids: 64}    # not enforced under seatbelt
max_compartments: 4
refexec:
  command: [refexec]
  timeout: 2m
  limits: {memory: 256m, cpus: "1", pids: 64}
  max_compartments: 2
  env_allow: []
```

refspawn renders each child's refexec config for the same backend: under
Seatbelt the child's refexec gets the same `store_root`, `pid_dir` and
`shared_host_scratch`, and a `deny_read` that is the operator's list plus
`spawn_root`.

The socket's directory is the access gate: it must be mode 0700 and owned
by the user refspawn runs as, and it must not be under Agenthof's
`refbox_socket_dir` (mounted into agent compartments) nor under
`spawn_root` (whose child directories are). Agenthof checks the same before
it dials.

`images` maps each agent name to the program its compartment runs — an
image under podman, an absolute executable path under Seatbelt. A child
workflow that names an agent not listed is refused before anything starts,
and Agenthof records the refusal. refspawn checks every entry against the
backend at start and refuses to serve if one is not runnable. Under podman,
pull the images yourself: refspawn runs podman with `--pull=never`.

## What one child gets

- A workspace store `agenthof-spawn-<run id>-work`, created when the child
  is provisioned and removed when it is torn down: under podman a named
  volume, under Seatbelt the directory `<store_root>/agenthof-spawn-<run
  id>-work`. Nothing else shares it.
- One compartment per distinct agent in the child's workflow, named
  `agenthof-spawn-<run id>-<agent>`, with direct network access denied and
  writes confined to two places — the child's workspace, and the child's
  socket directory `<spawn_root>/<run id>` at its own path. Under podman:
  a refbox container with `--network none`, a read-only root, every
  capability dropped, `no-new-privileges`, the host user's id, the memory /
  CPU / pid caps, `--timeout` as a backstop, `--pull=never`, and the
  workspace volume mounted read-write at `/work`. Under Seatbelt: a process
  under a generated sandbox profile, in its own session, with the workspace
  directory as its working directory and a kill timer for `timeout`. The
  agent listens on `<spawn_root>/<run id>/<agent>.sock`; the child's
  per-step gateway listens in the same directory.
- One `refexec` process on the host, configured from the `refexec` template
  plus the child's workspace, listening on
  `<spawn_root>/<run id>-exec/refexec.sock`. That directory is never
  mounted into any compartment: a child's agent reaches its refexec only
  through Agenthof's exec door.

Agents of one child share the child's workspace on purpose: a workflow's
steps run one at a time and pass work along it. The workspace is each
compartment's working directory on every backend; `/work` is the podman
mount point, not a contract, and under Seatbelt the workspace is the store
directory. Two children — siblings spawned in parallel, or a parent and its
child — never share a workspace.

## Backends

The ledger records the tier the child's set ran under (`child_confiner` on
the parent's `spawn` event), and `audit` prints the same grade it gives an
exec line. Both tiers share the host kernel; neither is a VM.

**podman** — rootless podman containers (Linux). `audit` says:

> shared-kernel container tier (rootless podman, --userns=keep-id); below any VM/microVM tier

**seatbelt** — macOS Seatbelt OS sandbox. `audit` says:

> shared-kernel OS-sandbox tier (macOS Seatbelt): same trust basis as podman — shared kernel, below any VM/microVM tier; direct network denied; writes scoped; host-readable; no resource caps; process teardown best-effort

Seatbelt is the weaker tier, honestly:

- **Host-readable.** An agent compartment can read the host filesystem
  except a deny list: the credential stores under the operator's home,
  `store_root` and `spawn_root` (apart from the child's own workspace and
  socket directory), `pid_dir`, and any `deny_read` paths. Another child's
  workspace is denied; anything else the operator's user can read, a child's
  agent can read.
- **Writes scoped** to the child's workspace and socket directory, plus
  device nodes such as `/dev/null` (the child's refexec also gives each
  command a private scratch directory);
  with `shared_host_scratch: true`, every compartment may also read and
  write the host's shared `/private/tmp`, and the ledger records it.
- **No resource caps.** `limits` is not enforced; only the compartment
  count and `timeout` bound a child.
- **Teardown is best-effort.** Compartments are killed by session and by
  the descendants refspawn can see; a descendant that detaches into a session
  of its own can outlive the child's teardown and the next start's sweep.
- Mach service lookups stay open (other than the LaunchServices family), so
  a service the OS exposes over Mach is reachable from the sandbox.

## The request

`POST /provision` with `{"child_run_id": "...", "agents": ["a", "b"]}`.
refspawn reserves the slots (`max_compartments` counts agent compartments
across every live child; a set that will not fit is refused whole), starts
the set, and answers `200` with one JSON line
`{"child_dir", "agent_sockets", "exec_socket", "tier", "tier_opts"}` once
every socket accepts a connection — `tier` (and any `tier_opts`) naming the
backend the set runs under, which Agenthof records on the parent's `spawn`
event. The response body then stays open for as long as the set lives. Agenthof closing it is the teardown request; the body ending on
refspawn's side means the set is gone.

Any other status is a refusal Agenthof records as
`spawn compartment unavailable`: a malformed request, a run id ending in
`-exec` (the suffix a child's exec directory reserves), an agent with no
image, the cap, a child that already has a live set — or whose compartment
names one holds — a start that failed, or sockets that never answered
within `ready_timeout`.

## Teardown, in order

1. `SIGTERM` to the child's refexec, which removes any exec compartment it
   still holds and exits.
2. Remove each agent compartment (`podman rm -f` under podman; under
   Seatbelt, a kill of its session and the descendants refspawn can see).
3. Remove the child's workspace — under podman, `podman volume rm`, possible
   only once nothing mounts it, which is why the order matters; under
   Seatbelt, removing the store directory unless a live compartment still
   records it. A workspace still held after a few retries is left for the
   next start's reap, never forced away from whatever is still writing to
   it.
4. The child's two directories.

At start-up, and again at shutdown, refspawn removes every compartment and
workspace whose name carries `agenthof-spawn-` (under Seatbelt: the
recorded processes whose start time still matches their record, and the
stores under `store_root`) and every directory under `spawn_root`: what a
previous refspawn left behind when it died with children in flight.

## Run it locally (Linux host with rootless podman)

(On macOS, use a Seatbelt config like the one above: build `refexec` and
`refspawn`, create the 0700 socket directory and the `store_root` and
`pid_dir` directories yourself, and run `refspawn -config` on it. Each
`images` entry is the executable that serves that agent.)

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
`may_spawn` on the agent that may spawn. `scripts/e2e-refspawn.sh` runs this
whole path with real podman; `scripts/e2e-refspawn-local.sh` runs the same
door and ledger proof on any machine, against a stand-in whose compartments
are host processes.

## Limits, stated

- A child's agents have direct network access denied, on either backend.
- The tiers differ (see [Backends](#backends)): Seatbelt is host-readable,
  has no resource caps and tears processes down best-effort; podman is a
  container with enforced caps. Neither is a VM.
- refspawn is a trusted host process running as the operator's user and
  driving the backend. Its socket directory's permissions and the mount
  namespace are the gate on who may ask.
- If `agenthof` is killed outright, its held requests close and refspawn
  tears the children down. If refspawn itself is killed outright, what
  happens to the child *compartments* depends on the backend. Under podman
  they live until podman's `--timeout` trips. Under Seatbelt teardown is
  best-effort: they are sandboxed host processes, and the next start kills
  the ones it can still match to their recorded process, but a descendant
  that detached into a session of its own can outlive both. Either way, the
  compartments and the child *workspaces* are reaped by name the next time
  refspawn starts. A child's
  *refexec* is a host process, not a compartment: on an ungraceful kill of
  refspawn it may be left running (idle, its socket directory removed on the
  next start) until the host or session ends.
- `max_compartments` counts agent compartments; each child's refexec is a
  host process whose transient exec compartments are bounded by its own
  `max_compartments`, not by this one.
- `max_compartments` must absorb teardown latency. A finished child's slots
  free only after its ordered teardown completes (refexec stop grace, then
  `volume rm` with retries), so a parent that spawns the next set immediately
  can see a transient `spawn compartment unavailable` refusal if the cap is
  sized exactly to one generation. Size it above the peak concurrent set.
- Run **one refspawn per podman user** (under Seatbelt, per `store_root` and
  `pid_dir`) — the supported topology. The start-up reap matches leftovers by
  the `agenthof-spawn-` name prefix across the whole namespace, but it spares
  the compartments, and (on podman) the stores, that a still-running sibling
  owns, so a concurrent sibling's live children survive it. Stay
  one-per-namespace all the same: under Seatbelt a store is spared only while a
  live agent compartment's record names it, leaving a narrow window around a
  child's store creation and its exec-only phase.
- A child always gets a fresh, empty workspace. Handing a child a shared or
  persistent workspace is not supported.
