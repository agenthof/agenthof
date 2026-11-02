# refexec — first-hand exec, governed

`refexec` serves Agenthof's exec door — the only exec path. An agent whose
config declares an `exec:` block never runs the command itself: it asks
Agenthof, Agenthof checks the allowlist and asks refexec over a Unix socket
only Agenthof dials, refexec runs the command in its own confined
compartment on the operator's host and attests what ran, and Agenthof
records that account on the run's ledger. The compartment is made by a
**confinement backend** the config selects: rootless podman on Linux, or
macOS Seatbelt. The two are different tiers with different limits; see
[Backends](#backends). When the agent runs inside refbox (its own mount
namespace, started with `--network none`), it has no path to refexec — it
reaches Agenthof only, and the socket is never mounted into its compartment.

refexec is a **host process**, like `agenthof` — it drives the backend
itself (it invokes `podman`, or `sandbox-exec`), so it is not containerized.
It is credential-less: no bearer is injected and nothing is materialized.

## Config (every key is required except `confiner` and the backend keys)

A podman config (the reference, [`exec-config/refexec.yaml`](exec-config/refexec.yaml)):

```yaml
confiner: podman                          # optional: podman (the Linux default) or seatbelt (the macOS default)
socket: /run/agenthof-exec/refexec.sock   # absolute; its directory must be mode 0700 and owned by the user refexec runs as
image: docker.io/library/busybox:1.36.1   # podman only: the image every compartment runs; pull it yourself, refexec never does
workspace:
  store: agenthof-work    # the workspace store: a podman volume here, a directory under store_root for seatbelt
  path: /work             # podman only; optional, defaults to /work: where the volume is mounted, and the working directory
timeout: 2m               # per-command deadline; set it to the agents' exec.timeout
limits:
  memory: 256m
  cpus: "1"
  pids: 64
compartments:
  max: 2                  # concurrent compartments; past the cap a request is refused, not queued
env_allow: []             # the ONLY variable names passed to the command, copied from refexec's own environment
```

A Seatbelt config replaces the podman-only keys (`image`, `workspace.path`)
with its own:

```yaml
confiner: seatbelt                        # optional on macOS, where it is the default
socket: /usr/local/var/agenthof/exec/refexec.sock   # absolute; same rules as above
store_root: /usr/local/var/agenthof/stores    # absolute; each workspace store is <store_root>/<workspace.store>
pid_dir: /usr/local/var/agenthof/pids         # absolute; must already exist; one record per live compartment
workspace:
  store: agenthof-work
# deny_read: [/usr/local/src]             # optional: extra subtrees compartments may not read
# shared_host_scratch: true               # optional, off by default; see Backends
timeout: 2m
limits: {memory: 256m, cpus: "1", pids: 64}   # required by the schema, NOT enforced under seatbelt
compartments:
  max: 2
env_allow: []
```

A key the selected backend does not consume is refused rather than ignored
(a podman config with `store_root`, a seatbelt config with `image`), and so
is the retired `workspace.volume`. `store_root` and `pid_dir` must be
absolute, and `store_root` short enough that a Unix socket path beneath it
fits the platform's limit. `pid_dir` must be on a filesystem that supports
hard links, which refexec uses to publish a compartment's record atomically;
on one that does not, a launch fails clearly rather than writing a record a
concurrent sweep could read half-written. On a host with no backend (anything but Linux and
macOS) there is no default and refexec refuses to start.

`refexec -config refexec.yaml -check` validates the file and prints the
launcher lines without listening: for podman, `socket=<path>` and
`workspace=<store>:<path>`; for seatbelt, `socket=<path>`,
`workspace=<store>` and `store_path=<host directory>`. A file that omits a
required key, sets a key the selected backend does not consume, uses the
retired `workspace.volume`, or names a `workspace.store` starting with
`refexec-` fails there. At start refexec probes the backend and removes the
leftover `refexec-` compartments of a refexec that is no longer running —
and any store under that prefix — before it opens the socket, which is why a
workspace store may not carry it; the compartments of another refexec that
is still running on the same backend are left alone. If the probe or the
sweep fails it exits without listening — there is no fallback to running a
command unconfined.

The socket's directory is the access gate. refexec checks at startup that it
is mode 0700 and owned by the user it runs as, and refuses to start
otherwise; Agenthof checks the same before it dials. Never point `socket`
into the refbox socket directory (`refbox_socket_dir` in `gateway.yaml`):
that directory is mounted into the agent's compartment.

## Backends

The ledger names the tier each command ran under, and `audit` states what
that tier does and does not guarantee. Both tiers share the host kernel;
neither is a VM.

**`podman` — rootless podman container (Linux).** The ledger and `audit` say:

> shared-kernel container tier (rootless podman, --userns=keep-id); below any VM/microVM tier

**`seatbelt` — macOS Seatbelt OS sandbox (macOS).** The ledger and `audit` say:

> shared-kernel OS-sandbox tier (macOS Seatbelt): same trust basis as podman — shared kernel, below any VM/microVM tier; direct network denied; writes scoped; host-readable; no resource caps; process teardown best-effort

Seatbelt is the weaker tier, and the difference is real:

- **Host-readable.** A compartment can read the host filesystem except a
  deny list: the credential stores under the operator's home (`.ssh`,
  `.aws`, `.gnupg`, `.config/gh`, `Library/Keychains`), `store_root`'s
  contents other than the compartment's own workspace and scratch space,
  `pid_dir`, and any `deny_read` paths. Anything else the operator's user
  can read, the command can read. (The compartment can still stat the
  `store_root` directory itself, which it needs to reach its own workspace;
  that exposes the directory's own metadata, not other stores' contents.)
- **Direct network denied.** The sandbox denies network access from the
  command. It is not a firewall for the host: Mach service lookups stay
  open (other than the LaunchServices family a confined `open` would use),
  so a service the OS exposes over Mach is reachable.
- **Writes scoped** to the workspace directory and a private scratch
  directory (`<store_root>/.scratch/<compartment>`, exported as `TMPDIR`
  and removed with the compartment). With `shared_host_scratch: true` every
  compartment may also read and write the host's shared `/private/tmp`; the
  ledger records `shared-host-scratch` and `audit` shows it.
- **No resource caps.** `limits` is accepted but not enforced; refexec logs
  that at start. A runaway command is bounded only by `timeout` and the
  compartment cap.
- **Process teardown is best-effort.** Each command runs in its own session
  and `timeout` is enforced by a timer inside refexec; at the deadline or on
  cancel refexec kills the session and the descendants it can see. A
  descendant that detaches into a session of its own can outlive that, and
  the next start's sweep cannot reach it. Every live compartment has a pid
  record under `pid_dir`; at start refexec kills a recorded process only if
  its start time still matches the record, so a reused pid is never
  signalled.

## What one command gets

**Under podman**, per `POST /run`, one `podman run`: `--network none`, a
read-only root, a tmpfs at `/tmp`, every capability dropped,
`no-new-privileges`, the host user's id (`--userns=keep-id`), the memory /
CPU / pid caps above, `--timeout` as a backstop, `--pull=never`, and
exactly one mount — the workspace volume, read-write, at the workspace
path.

**Under Seatbelt**, one process started by `sandbox-exec` under a generated
profile (the properties above), in its own session, with the workspace
directory as its working directory.

On both, the command's environment is the `env_allow` names refexec's own
environment holds, plus `TMPDIR` pointing at the compartment's scratch
space; nothing else is inherited (under podman an image's own `ENV` layer
adds what it adds, and refexec does not see it). Combined stdout+stderr is
captured up to 1 MiB and then cut with a marker.

## What refexec tells Agenthof about each command

The response carries the exit code, the output (capped), `output_sha` —
the SHA-256 of exactly the output string returned, so Agenthof and the
agent can both check it — `truncated`, `output_bytes` (the full count), and
refexec's first-hand account, which Agenthof records on the `exec` event as
`runtime_attestation`: the argv it ran, the per-request id (also the
compartment's name, the key into refexec's own log), the host pid refexec
held first-hand (never a pid inside the compartment: the `podman run`
client under podman, the sandboxed process itself under Seatbelt), the
environment variable names it injected (always including `TMPDIR`), and the
`confiner` tier and any `confiner_opts` it applied. Never a value, never
the output. Agenthof rejects the call if the attested argv is not the one it
authorized.

## The workspace

The workspace is the compartment's working directory on every backend, so a
relative path resolves against it everywhere. That is the only path
convention a command or agent may rely on. The absolute path differs:

- **podman:** a named volume mounted read-write at `workspace.path` (default
  `/work`) into every refexec compartment, and at the same path into the
  agent's refbox compartment (`REFBOX_WORKSPACE_VOLUME` on
  `deploy/refbox/refbox-run.sh`). `/work` is podman's mount point, not a
  contract. Its life is the recipe's: `refexec-run.sh` creates the volume,
  runs share it, and tearing the recipe down (`podman volume rm`) drops it.
- **seatbelt:** a plain host directory, `<store_root>/<workspace.store>`,
  which the compartment sees at that real path. There is no `/work`.
  `refexec-run-seatbelt.sh` creates it (mode 0700); removing the directory
  tears it down.

One refexec per refbox — or one per spawned child, shared by that child's
agents, when `refspawn` starts it (see
[`deploy/refspawn/README.md`](../refspawn/README.md)).

## Run it locally (Linux host with rootless podman)

The reference config's `socket` is `/run/agenthof-exec/refexec.sock`: that
is the reference placement, and creating it needs root. As a rootless user,
copy `deploy/refexec/exec-config/refexec.yaml` somewhere writable and set
`socket` in the copy to `$XDG_RUNTIME_DIR/agenthof-exec/refexec.sock`,
written out as the absolute path (refexec does not expand variables):

```
go build -o /tmp/refexec ./deploy/refexec
podman pull docker.io/library/busybox:1.36.1
sed "s|/run/agenthof-exec|$XDG_RUNTIME_DIR/agenthof-exec|" deploy/refexec/exec-config/refexec.yaml >/tmp/refexec.yaml
REFEXEC_BIN=/tmp/refexec REFEXEC_CONFIG=/tmp/refexec.yaml deploy/refexec/refexec-run.sh
```

`refexec-run.sh` validates the config, prepares the 0700 directory of the
config's `socket`, creates the workspace volume and hands over to refexec.
The agent's `exec.url` must name the same socket path. Then start the agent
with `REFBOX_WORKSPACE_VOLUME=agenthof-work deploy/refbox/refbox-run.sh`, and
declare the door on the agent:

```yaml
exec:
  runtime: refexec
  url: unix:///run/agenthof-exec/refexec.sock
  timeout: 2m
  allow:
    - exe: cat
```

`scripts/e2e-refexec.sh` runs this whole path with real podman;
`scripts/e2e-refexec-local.sh` runs the same door and ledger proof on any
machine, against a stand-in that runs commands directly on the host.

## Run it locally (macOS host, Seatbelt)

Write a Seatbelt config like the one above with absolute paths of your own,
create the `pid_dir` yourself (it must exist before refexec starts), and
start refexec through the macOS launcher, which validates the config, creates
the 0700 socket directory and the 0700 store directory, and hands over to
refexec:

```
go build -o /tmp/refexec ./deploy/refexec
mkdir -p -m 0700 /usr/local/var/agenthof/pids
REFEXEC_BIN=/tmp/refexec REFEXEC_CONFIG=/tmp/refexec-seatbelt.yaml deploy/refexec/refexec-run-seatbelt.sh
```

The agent's `exec.url` must name the config's `socket`. There is no refbox
recipe for macOS: the agent runs wherever the operator runs it, and the
workspace is the store directory on the host.

`scripts/e2e-refexec-seatbelt.sh` runs this whole path with the real
`sandbox-exec`: the ledger names the Seatbelt tier, a command that tries the
network is refused inside its compartment, a write outside the store fails
and leaves no file, and no PID record or scratch dir is left behind.

## Limits, stated

- Direct network access is denied in every compartment, on either backend.
  Builds and tests on vendored code work; installs and fetches do not.
- The tiers differ (see [Backends](#backends)): Seatbelt is host-readable,
  has no resource caps and tears processes down best-effort; podman is a
  container with enforced caps. Neither is a VM.
- refexec is a trusted host process running as the operator's user and
  driving the backend. A compromised refexec could misreport, as a
  compromised sandbox could; the ledger's line is its first-hand account, not
  proof against it. The socket directory's permissions and the mount
  namespace are the gate on who may ask.
- The record says what ran and what it printed. The files it read are the
  agent's, before, during and after; refexec does not serialize concurrent
  commands on the workspace.
- Cancelling a command — Agenthof's `exec.timeout`, or Agenthof hanging up —
  removes the compartment (`podman rm -f` under podman; a best-effort kill of
  the session under Seatbelt). Under podman, `timeout` here is also passed as
  podman's `--timeout`, a backstop that holds if refexec itself dies.
- One synchronous connection per command, for the command's whole duration.
