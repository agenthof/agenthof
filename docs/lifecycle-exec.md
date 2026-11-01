# The life of an exec

One allowlisted command, from the moment a fronted agent asks Agenthof to
run it to the line the ledger keeps. This is the exec door. For the run it
happens inside, see [`lifecycle.md`](lifecycle.md). For the YAML, see
[`reference/config.md`](reference/config.md#exec). For the executable proof —
the run, the refusals, and the rendered audit line — see the testscript
[`cmd/agenthof/testdata/script/door_exec_runtime.txtar`](../cmd/agenthof/testdata/script/door_exec_runtime.txtar).

The exec door is first-hand. The agent never runs the command: it asks
Agenthof to, and a trusted operator-side runtime the operator declared —
`refexec`, in `deploy/refexec/`, a host process next to Agenthof — runs it
in its own confined compartment (rootless podman on Linux, macOS Seatbelt;
see [the confinement backends](#the-confinement-backends)) and attests to
Agenthof what ran.
Agenthof authorizes the command, forwards it, checks the runtime's account
against what it authorized, and records that account. Agenthof itself does
not run the command, and an agent's own report of one is not a record. For
the runtime, see [`deploy/refexec/README.md`](../deploy/refexec/README.md).

```
  agent (in refbox)          Agenthof                          refexec (host)            ledger
    |  POST /exec/run           |                                  |                         |
    |  {command}                |-- match config allowlist         |                         |
    | <-- 403                   |-- no match: exec, refused ----------------------------------->|
    |                           |-- socket dir private? no: exec, failed ---------------------->|
    |                           |-- POST /run {command} ---------->| confined compartment      |
    |                           |                                  |   direct network denied,  |
    |                           |                                  |   workspace rw            |
    |                           |                                  |   runs argv, captures     |
    |                           | <-- {exit_code, output,          |   output (1 MiB cap)      |
    |                           |      output_sha, truncated,      |                         |
    |                           |      output_bytes, attestation}  |                         |
    |                           |-- attestation names this argv? output_sha matches?         |
    |                           |   no: exec, failed ---------------------------------------->|
    | <-- {exit, output,        |-- exec, mode runtime, runtime_attestation ---------------->|
    |      truncated}           |                                  |                         |
```

## When the door exists

Any agent may declare `exec`; every agent is fronted. The block names the
runtime that serves the door, that runtime's socket, the deadline Agenthof
puts on each call, and a non-empty `allow` list:

```yaml
exec:
  runtime: refexec
  url: unix:///run/agenthof-exec/refexec.sock
  timeout: 2m
  allow:
    - exe: cat
```

`runtime` names the trusted runtime (only `refexec` exists), `url` is its
Unix socket — a trusted runtime is reached only over a local socket, in a
directory only the user Agenthof runs as can enter, and never under
`refbox_socket_dir`, which is mounted into agent compartments — and
`timeout` is the deadline Agenthof puts on the whole call. All four fields
are required: there is no exec without an operator-run runtime, and a block
that omits any of them is rejected at `apply`, each missing field by name.
The retired key `mode` is rejected at `apply` too, by name and with the
replacement stated; a config is never read with that key silently dropped.
An `exec` block on an agent whose `execution` is not `fronted` (including
the removed value `contained`) is rejected the same way. See
[`reference/config.md`](reference/config.md#exec).

The trade, stated plainly: the exec door requires an operator-run `refexec`
— on a Linux host with rootless podman, or on a macOS host using the
Seatbelt tier, which is a weaker tier (see
[the confinement backends](#the-confinement-backends)). There is no
runtime-free exec.

For the duration of that agent's step, Agenthof starts a listener on
`127.0.0.1` and an ephemeral port, reachable only from the host Agenthof
itself runs on (or, with `refbox_socket_dir`, a Unix socket in that
directory). The same listener serves the agent's tools, when it has any,
and the exec door. The call out to the agent carries two extra headers:

| Header | Carries |
| --- | --- |
| `X-Agenthof-Proxy-URL` | the address of the listener started for this step |
| `X-Agenthof-Run-Token` | a token minted just for this step |

The route requires `Authorization: Bearer <token>`. A request without the
matching token is rejected before the door runs. The token is never written
to the ledger. When the step finishes, the listener shuts down and the token
stops working.

Every fronted step gets this listener and both headers, whether or not the
agent declares `exec` or `tools`. The agent uses the doors it needs and
ignores the rest.

If the listener fails to start, the step fails immediately, with no bounce,
the same way a tools step fails when its proxy cannot start.

## The allowlist

Agenthof matches the argv against the agent's `allow` list. An entry matches
when `argv[0]` equals `exe` exactly and `args_prefix` is a prefix of the
arguments that follow. The rest of the argv is unconstrained. An empty
`args_prefix` matches any arguments of that executable. An empty argv matches
nothing. The exact rule is in
[`reference/config.md`](reference/config.md#exec).

Allowlisting an executable trusts that program's whole capability surface:
`go` with a prefix of `test` still permits whatever flags `go test` accepts.
An entry whose executable is a shell or interpreter and whose prefix is an
eval flag (`sh -c`, `python -c`, and the like) matches arbitrary commands,
and Agenthof does not detect or reject those entries. Writing a safe
allowlist is the operator's obligation. The compartment refexec runs the
command in is what bounds the damage a bad entry can do.

## Asking Agenthof to run it

The agent `POST`s `/exec/run` with `{"command": ["cat", "/work/agent-note.txt"]}`
and the run token. Agenthof, in order:

1. matches the argv against `allow`. No match: an `exec` event with status
   `refused`, reason `command is not on the exec allowlist`, `mode: runtime`,
   and a `403`. refexec is never asked. An argv the ledger cannot carry (too
   many arguments, an argument too long, or one holding a control character)
   is refused the same way, reason `command exceeds the ledger's argv
   bounds`, before anything runs.
2. checks that the socket's directory is mode `0700` and owned by the user
   Agenthof runs as — the same gate refexec applies when it starts. If not:
   an `exec` event with status `failed` and a `502`; nothing is dialed.
3. calls refexec over the socket and waits, at most `timeout`.
4. checks refexec's answer: the attestation must be refexec's — naming the
   runtime the agent declared — and must name exactly the argv that was
   authorized, and `output_sha` must be the SHA-256 of the output that came
   back. Any failure of the call — refexec unreachable, an error status
   (including refexec refusing because its compartment cap is reached), a
   malformed or oversized answer, a missing or malformed attestation, a
   different argv, a wrong hash, the deadline, or Agenthof shutting the step
   down mid-call — is one `exec` event with status `failed`, a fixed reason,
   and a `502`. A door that ran nothing still leaves a line.
5. appends the `exec` event and answers the agent with
   `{"exit": 0, "output": "…", "truncated": false}`.

A body that is not JSON is answered `400` and records nothing.

refexec, per call, starts one compartment under the confinement backend its
config selects (below). Under rootless podman that is `--network none`, a
read-only root with a tmpfs scratch at `/tmp`, every capability dropped, no
new privileges, the host user's id, the operator's memory / CPU / pid caps,
`--pull=never`, and one volume — the workspace, read-write, at the
workspace path, which is also the working directory. Under Seatbelt it is
a host process started under a generated sandbox profile that denies direct
network access, scopes writes to the workspace directory and a private
scratch directory, and runs in its own session, with the workspace
directory as its working directory. On either backend the command's
environment is only the `env_allow` names from refexec's config that
refexec's own environment holds, plus `TMPDIR` pointing at the
compartment's scratch space (a podman image's own `ENV` layer adds what it
adds; refexec does not see it). Combined stdout and stderr are captured up
to 1 MiB and cut with a marker beyond that. Cancelling the call (the
deadline, or Agenthof hanging up) removes the compartment. refexec keeps no
state between calls beyond its cap on concurrent compartments; a call past
that cap is refused, never queued.

## The confinement backends

The operator picks the backend with `confiner:` in refexec's config; with
none named, the host's default is used (podman on Linux, Seatbelt on
macOS). refexec probes the chosen backend before it opens its socket — for
Seatbelt, that a write outside the workspace is denied and one inside it
succeeds — and refuses to start if the probe fails; there is no fallback to
running a command unconfined. The two backends are not equivalent:

- **`podman` — the container tier.** A rootless-podman container on a shared
  kernel: the command sees only its image and the workspace volume, with
  the memory / CPU / pid caps enforced and the container removed on
  cancel. A shared kernel is still below any VM tier.
- **`seatbelt` — the macOS OS-sandbox tier.** A host process under a
  Seatbelt profile, on the same shared kernel, and weaker than the
  container tier in ways an operator must weigh: it is **host-readable**
  (the command can read the host filesystem except a deny list — the
  credential stores under the operator's home, refexec's own store and pid
  directories, and any `deny_read` paths the operator adds); direct network
  access is denied and writes are scoped to the workspace and a private
  scratch directory; it has **no resource caps** (the `limits` values are
  not enforced); and **process teardown is best-effort** — a descendant
  that detaches into a new session can outlive the compartment's removal
  (the next refexec start sweeps the leftovers it can still match, but
  cannot reach a process that has detached).

The ledger names the backend that ran each command (below), so a reader
sees which tier an exec line stands on.

## The record

| Field | What it holds |
| --- | --- |
| `command` | the argv Agenthof authorized (and verified refexec attested) |
| `exit_code` | the command's exit status, as refexec reports it |
| `output_sha` | refexec's SHA-256 of the output it returned; Agenthof recomputed it over what it received |
| `mode` | `runtime` |
| `status` | `succeeded` when the exit is `0`, `failed` otherwise — or `failed` with a `reason` when the door itself failed, or `refused` with a `reason` |
| `runtime_attestation` | refexec's first-hand account: `runtime: refexec`, `session` (the compartment's name, the key into refexec's own log), `command`, `pid` (the host pid refexec held first-hand — never a pid inside the compartment), `spawn: 1`, `env_names` (the variable names refexec injected, always including `TMPDIR`), `confiner` and `confiner_opts` (below), and empty `credential_env` / `materialization` (refexec is credential-less) |

Inside `runtime_attestation`, `confiner` is the tier the compartment ran
under, as refexec names it (`podman` or `seatbelt` today), and
`confiner_opts` lists any per-deployment loosening that tier applied (for
Seatbelt, `shared-host-scratch` when the operator opted into a scratch
directory shared with the host). Both are the runtime's own statement of
what it applied, recorded verbatim; a tier this version does not recognise
is shown by name and ungraded. The ledger records the tier's name, not the
policy behind it, so the grade `audit` shows is a statement about the tier
as a whole: what that kind of confinement does and does not guarantee, never
a claim about one configuration of it. A line from a runtime that predates
these fields carries no tier and renders without one.

The event also carries the run's delegation binding, like every other event
in the run. It carries `output_sha`, never the output itself. The output
goes back to the agent; what the agent does with it — for instance, return
it as the step's artifact — is recorded the way any step result is.

`audit` renders it as
`exec cat /work/agent-note.txt — exit 0 (runtime) [runtime-attested: refexec cat /work/agent-note.txt pid 4242 spawn 1; confiner: podman — shared-kernel container tier (rootless podman, --userns=keep-id); below any VM/microVM tier]`,
on a failed exit too; a refusal renders as `exec … refused — <reason>` and a
door failure as `exec … failed — <reason>`. Under Seatbelt the suffix reads
`; confiner: seatbelt — shared-kernel OS-sandbox tier (macOS Seatbelt): same
trust basis as podman — shared kernel, below any VM/microVM tier; direct
network denied; writes scoped; host-readable; no resource caps; process
teardown best-effort`, with `; shared host scratch` appended when that
loosening is on. The grade is the tier's honest limits, stated on the line
so a reader need not know the backends to read it.

## The retired agent-asserted routes

`/exec/authorize` and `/exec/attest` once let an agent report a command it
had run itself. That path is gone: exec is first-hand only. The two routes
remain only so that a call to them is a recorded refusal rather than an
unrecorded error. A `POST` to either, on any agent, is answered `403` and
recorded as an `exec` event with status `refused`, reason `exec on this
agent is first-hand: authorize and attest are not available`, and `mode:
runtime` — an agent's own report cannot land on the ledger. Likewise
`/exec/run` on an agent that declares no `exec` is refused before the
allowlist is consulted, with reason `first-hand exec is not declared for
this agent`, and recorded the same way.

Ledgers written before exec became first-hand only may hold `exec` events
with `mode: attested`: the agent's own report of a command — its argv, exit
code and output hash, with no `runtime_attestation`. They still verify (the
chain is over the exact bytes written) and `audit` still renders them, as
`exec <argv> — exit <n> (attested)`. Read such a line for what it was: the
agent's word, not a runtime's.

## The workspace

The workspace is the compartment's working directory on every backend, so
a relative path resolves against the workspace wherever refexec runs; that
is the only path convention an agent may rely on. An absolute path to it
depends on the backend. Under rootless podman the workspace is a named
volume, mounted read-write at refexec's `workspace.path` (`/work` by
default) into every refexec compartment, and at the same path into the
agent's refbox compartment (`REFBOX_WORKSPACE_VOLUME` on the refbox recipe,
which must agree). `/work` is podman's mount point, not a contract of the
exec door. Under Seatbelt the workspace is a plain host directory,
`<store_root>/<store>`, which the compartment sees at that real path; there
is no `/work`. Its life is the recipe's, not a run's: refexec's launcher
creates it, every run shares it, and the operator removes it (`podman volume
rm`, or deleting the store directory) when tearing the recipe down —
nothing removes it automatically. One refbox, one refexec, one workspace.
refbox starts before any run exists, so nothing can mint a workspace per
run. Agenthof stays out of storage.

## What the record does and does not prove

The guarantee, stated plainly: *refexec, a runtime the operator started
and trusts, ran exactly this argv in a compartment under the tier the
record names, with direct network access denied, and this is its account
of the exit and the output; Agenthof authorized the argv, checked the
account against it, and recorded it — and did not run the command.*

- It is refexec's word. A compromised refexec could misreport, as a
  compromised sandbox could; the record is first-hand, not tamper-proof.
  Trusting refexec is the same class of trust as trusting refbox to
  contain, or a declared bridge on the tool door.
- It says what ran and what it printed. The files the command read are the
  agent's, before, during and after; there is no input-integrity claim and
  no serialization of concurrent commands on the workspace.
- It is offline. Commands that need the network fail inside their
  compartment, and the failure is recorded first-hand.
- The tier on the line is the tier's limit, not a stronger one. Both
  tiers share the host kernel, and both sit below a VM. Seatbelt is the
  weaker of the two: the command can read most of the host filesystem
  (minus a deny list), there are no memory / CPU / pid caps, and
  teardown of what a command left running is best-effort. Read the exec
  line for the tier it names, and choose the backend knowing that.
- A refusal is first-hand evidence that this door was asked and said no. It
  is not evidence about what the agent did next inside its own compartment;
  that compartment's confinement is the operator's, and Agenthof does not
  verify it.
- The event joins the run's hash-chained ledger, with the same limits as
  every other event; see [`lifecycle.md`](lifecycle.md).

## What ships today vs what is not a capability

| Shipped today | Not a capability |
| --- | --- |
| the first-hand door: the allowlist check, then `refexec` runs the command in a compartment with direct network access denied — rootless podman on Linux, Seatbelt on macOS — and Agenthof records its account as `exec` with `runtime_attestation`, naming the tier; the retired agent-asserted routes answer a recorded refusal | Agenthof running the command itself — rejected at `apply`; exec containment is the operator's runtime's job, and Agenthof's job is to govern and record |
| historical `mode: attested` events in old ledgers verify and render | an agent-reported exec — retired; no new such event can be created |
| | a network allowlist for first-hand commands (direct network access is denied); a confinement tier stronger than a shared-kernel container (a VM or micro-VM backend); a runtime other than `refexec`; exec without an operator-run runtime |

Only shipped behavior is a guarantee.
