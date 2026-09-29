# refexec — first-hand exec, governed

`refexec` serves Agenthof's exec door first-hand. An agent whose config
declares `exec.mode: runtime` never runs the command itself: it asks
Agenthof, Agenthof checks the allowlist and asks refexec over a Unix socket
only Agenthof dials, refexec runs the command in its own rootless-podman
compartment on the operator's host and attests what ran, and Agenthof
records that account on the run's ledger. The agent has no path to refexec:
it talks to Agenthof only.

refexec is a **host process**, like `agenthof` — it invokes `podman` itself,
so it is not containerized. It is credential-less: no bearer is injected and
nothing is materialized.

## Config (every key is required; nothing is defaulted)

```yaml
socket: /run/agenthof-exec/refexec.sock   # absolute; its directory must be mode 0700 and owned by the user refexec runs as
image: docker.io/library/busybox:1.36.1   # the image every compartment runs; pull it yourself, refexec never does
workspace:
  volume: agenthof-work   # the podman volume shared with the agent's refbox compartment
  path: /work             # mounted rw there, and the working directory
timeout: 2m               # podman --timeout backstop; set it to the agents' exec.timeout
limits:
  memory: 256m
  cpus: "1"
  pids: 64
compartments:
  max: 2                  # concurrent compartments; past the cap a request is refused, not queued
env_allow: []             # the ONLY variable names passed to the command, copied from refexec's own environment
```

`refexec -config refexec.yaml -check` validates the file and prints
`socket=<path>` and `workspace=<volume>:<path>` without listening; a file
that omits any key fails there.

The socket's directory is the access gate. refexec checks at startup that it
is mode 0700 and owned by the user it runs as, and refuses to start
otherwise; Agenthof checks the same before it dials. Never point `socket`
into the refbox socket directory (`refbox_socket_dir` in `gateway.yaml`):
that directory is mounted into the agent's compartment.

## What one command gets

Per `POST /run`, one `podman run`: `--network none`, a read-only root, a
tmpfs at `/tmp`, every capability dropped, `no-new-privileges`, the host
user's id (`--userns=keep-id`), the memory / CPU / pid caps above, `--timeout`
as a backstop, `--pull=never`, and exactly one mount — the workspace volume,
read-write, at the workspace path. The command's environment is the
`env_allow` names refexec's own environment holds, nothing else (the image's
own `ENV` layer adds what it adds; refexec does not see it). Combined
stdout+stderr is captured up to 1 MiB and then cut with a marker.

## What refexec tells Agenthof about each command

The response carries the exit code, the output (capped), `output_sha` —
the SHA-256 of exactly the output string returned, so Agenthof and the
agent can both check it — `truncated`, `output_bytes` (the full count), and
refexec's first-hand account, which Agenthof records on the `exec` event as
`runtime_attestation`: the argv it ran, the per-request id (also the
compartment's container name, the key into refexec's own log), the host pid
of the `podman run` client it held (never a pid inside the compartment),
and the environment variable names it injected. Never a value, never the
output. Agenthof rejects the call if the attested argv is not the one it
authorized.

## The workspace

The workspace is a named podman volume, mounted read-write at the same path
into the agent's refbox compartment (`REFBOX_WORKSPACE_VOLUME` on
`deploy/refbox/refbox-run.sh`) and into every refexec compartment. Its life
is the recipe's: `refexec-run.sh` creates it, runs share it, and tearing the
recipe down (`podman volume rm`) drops it. One refexec per refbox.

## Run it locally (Linux host with rootless podman)

```
go build -o /tmp/refexec ./deploy/refexec
podman pull docker.io/library/busybox:1.36.1
REFEXEC_BIN=/tmp/refexec deploy/refexec/refexec-run.sh
```

`refexec-run.sh` validates the config, prepares the socket's 0700 directory,
creates the workspace volume and hands over to refexec. Then start the agent
with `REFBOX_WORKSPACE_VOLUME=agenthof-work deploy/refbox/refbox-run.sh`, and
declare the door on the agent:

```yaml
exec:
  mode: runtime
  runtime: refexec
  url: unix:///run/agenthof-exec/refexec.sock
  timeout: 2m
  allow:
    - exe: cat
```

`scripts/e2e-refexec.sh` runs this whole path with real podman;
`scripts/e2e-refexec-local.sh` runs the same door and ledger proof on any
machine, against a stand-in that runs commands directly on the host.

## Limits, stated

- Offline only: every compartment runs with no network. Builds and tests on
  vendored code work; installs and fetches do not.
- refexec is a trusted host process running as the operator's user and
  invoking podman. A compromised refexec could misreport, as a compromised
  sandbox could; the ledger's line is its first-hand account, not proof
  against it. The socket directory's permissions and the mount namespace
  are the gate on who may ask.
- The record says what ran and what it printed. The files it read are the
  agent's, before, during and after; refexec does not serialize concurrent
  commands on the workspace.
- Cancelling a command — Agenthof's `exec.timeout`, or Agenthof hanging up —
  removes the compartment (`podman rm -f`). `timeout` here is only a
  backstop.
- One synchronous connection per command, for the command's whole duration.
