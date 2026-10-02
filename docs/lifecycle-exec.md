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
in its own rootless-podman compartment and attests to Agenthof what ran.
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
    |                           |-- POST /run {command} ---------->| podman run --network none |
    |                           |                                  |   --read-only, /work rw   |
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
— a Linux host with rootless podman, like the rest of the reference
runtimes. There is no runtime-free exec.

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

An agent that declares `exec` and no tools still gets this listener. An agent
that declares neither never sees the two headers.

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

refexec, per call, starts one compartment: `--network none`, a read-only
root with a tmpfs scratch at `/tmp`, every capability dropped, no new
privileges, the host user's id, the operator's memory / CPU / pid caps,
`--pull=never`, and one volume — the workspace, read-write, at the
workspace path, which is also the working directory. The command's
environment is only the `env_allow` names from refexec's config that
refexec's own environment holds (an image's own `ENV` layer adds what it
adds; refexec does not see it). Combined stdout and stderr are captured up
to 1 MiB and cut with a marker beyond that. Cancelling the call (the
deadline, or Agenthof hanging up) removes the compartment. refexec keeps no
state between calls beyond its cap on concurrent compartments; a call past
that cap is refused, never queued.

## The record

| Field | What it holds |
| --- | --- |
| `command` | the argv Agenthof authorized (and verified refexec attested) |
| `exit_code` | the command's exit status, as refexec reports it |
| `output_sha` | refexec's SHA-256 of the output it returned; Agenthof recomputed it over what it received |
| `mode` | `runtime` |
| `status` | `succeeded` when the exit is `0`, `failed` otherwise — or `failed` with a `reason` when the door itself failed, or `refused` with a `reason` |
| `runtime_attestation` | refexec's first-hand account: `runtime: refexec`, `session` (the compartment's name, the key into refexec's own log), `command`, `pid` (the host pid of the `podman run` client refexec held — never a pid inside the compartment), `spawn: 1`, `env_names` (the variable names refexec injected), and empty `credential_env` / `materialization` (refexec is credential-less) |

The event also carries the run's delegation binding, like every other event
in the run. It carries `output_sha`, never the output itself. The output
goes back to the agent; what the agent does with it — for instance, return
it as the step's artifact — is recorded the way any step result is.

`audit` renders it as
`exec cat /work/agent-note.txt — exit 0 (runtime) [runtime-attested: refexec cat /work/agent-note.txt pid 4242 spawn 1]`,
on a failed exit too; a refusal renders as `exec … refused — <reason>` and a
door failure as `exec … failed — <reason>`.

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

The workspace is a named podman volume, mounted read-write at `/work` into
the agent's refbox compartment (`REFBOX_WORKSPACE_VOLUME` on the refbox
recipe) and at refexec's `workspace.path`, which must also be `/work`, into
every refexec compartment. Its life is the recipe's, not a run's: refexec's
launcher creates it, every run shares it, and the operator removes it
(`podman volume rm`) when tearing the recipe down — nothing removes it
automatically. One refbox, one refexec, one volume. refbox starts before any
run exists, so nothing can mint a volume per run. Agenthof stays out of
storage.

## What the record does and does not prove

The guarantee, stated plainly: *refexec, a runtime the operator started
and trusts, ran exactly this argv in a compartment with no network, and
this is its account of the exit and the output; Agenthof authorized the
argv, checked the account against it, and recorded it — and did not run
the command.*

- It is refexec's word. A compromised refexec could misreport, as a
  compromised sandbox could; the record is first-hand, not tamper-proof.
  Trusting refexec is the same class of trust as trusting refbox to
  contain, or a declared bridge on the tool door.
- It says what ran and what it printed. The files the command read are the
  agent's, before, during and after; there is no input-integrity claim and
  no serialization of concurrent commands on the workspace.
- It is offline. Commands that need the network fail inside their
  compartment, and the failure is recorded first-hand.
- A refusal is first-hand evidence that this door was asked and said no. It
  is not evidence about what the agent did next inside its own compartment;
  that compartment's confinement is the operator's, and Agenthof does not
  verify it.
- The event joins the run's hash-chained ledger, with the same limits as
  every other event; see [`lifecycle.md`](lifecycle.md).

## What ships today vs what is not a capability

| Shipped today | Not a capability |
| --- | --- |
| the first-hand door: the allowlist check, then `refexec` runs the command in a no-network compartment and Agenthof records its account as `exec` with `runtime_attestation`; the retired agent-asserted routes answer a recorded refusal | Agenthof running the command itself — rejected at `apply`; exec containment is the operator's runtime's job, and Agenthof's job is to govern and record |
| historical `mode: attested` events in old ledgers verify and render | an agent-reported exec — retired; no new such event can be created |
| | a network allowlist for first-hand commands (they run with no network); a runtime other than `refexec`; exec without an operator-run runtime |

Only shipped behavior is a guarantee.
