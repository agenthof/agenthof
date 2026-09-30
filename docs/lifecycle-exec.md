# The life of an exec

One allowlisted command, from the moment a fronted agent asks permission to
the line the ledger keeps. This is the exec door. For the run it happens
inside, see [`lifecycle.md`](lifecycle.md). For the YAML, see
[`reference/config.md`](reference/config.md#exec). For the executable proof —
authorize, attest, and the rendered audit line — see the testscript
[`cmd/agenthof/testdata/script/door_exec.txtar`](../cmd/agenthof/testdata/script/door_exec.txtar).
The first-hand door has its own proof, [`door_exec_runtime.txtar`](../cmd/agenthof/testdata/script/door_exec_runtime.txtar).

```
  agent                         Agenthof                         ledger
    |  POST /exec/authorize         |                               |
    |  {command}                    |-- match config allowlist      |
    |                               |                               |
    | <-- {allowed: true}           |   (no event)                  |
    | <-- {allowed: false}          |-- exec, status refused ------>|
    |                               |                               |
    |  runs the command in the      |                               |
    |  operator's sandbox           |   (Agenthof does not run it)  |
    |                               |                               |
    |  POST /exec/attest            |                               |
    |  {command, exit, output_sha}  |-- exec, mode attested ------->|
    | <-- 204                       |                               |
```

## When the door exists

Any agent may declare `exec`; every agent is fronted. The block names a
`mode` and a non-empty `allow` list. `mode: attested` is the door most of
this page describes: the agent runs the command and reports it. `mode:
runtime` is the first-hand door: a trusted operator-side runtime runs the
command on the agent's behalf and attests it — see "The first-hand door"
below. Agenthof itself running the command is not a mode and any other
value is rejected at `apply`. An `exec` block on an agent whose `execution`
is not `fronted` (including the removed value `contained`) is rejected the
same way.

For the duration of that agent's step, Agenthof starts a listener on
`127.0.0.1` and an ephemeral port, reachable only from the host Agenthof
itself runs on. The same listener serves the agent's tools, when it has any,
and the exec door. The call out to the agent carries two extra headers:

| Header | Carries |
| --- | --- |
| `X-Agenthof-Proxy-URL` | the address of the listener started for this step |
| `X-Agenthof-Run-Token` | a token minted just for this step |

Both routes require `Authorization: Bearer <token>`. A request without the
matching token is rejected before authorize or attest runs. The token is never
written to the ledger. When the step finishes, the listener shuts down and
the token stops working.

An agent that declares `exec` and no tools still gets this listener. An agent
that declares neither never sees the two headers.

If the listener fails to start, the step fails immediately, with no bounce,
the same way a tools step fails when its proxy cannot start.

## Asking permission

The agent `POST`s `/exec/authorize` with a JSON body `{"command": ["go", "test", "./..."]}`.
`command` is the argv, executable first.

Agenthof matches that argv against the agent's `allow` list. An entry matches
when `argv[0]` equals `exe` exactly and `args_prefix` is a prefix of the
arguments that follow. The rest of the argv is unconstrained. An empty
`args_prefix` matches any arguments of that executable. An empty argv matches
nothing. The exact rule is in
[`reference/config.md`](reference/config.md#exec).

The response is JSON, `{"allowed": true}` or `{"allowed": false}`:

- **Allowed.** No ledger event. Permission for a conforming agent is not
  itself a record that the command ran.
- **Refused.** The ledger records an `exec` event with status `refused`,
  reason `command is not on the exec allowlist`, the argv in `command`, and
  `mode: attested`. That line is evidence the request reached this door.

A body that is not JSON is rejected and records nothing.

## Running it

A conforming agent runs an allowed command in the **operator's sandbox**, then
reports the result. Agenthof does not start the process, does not see its
output, and does not confine it. Containment is the sandbox the operator
provides. Allowlisting an executable trusts that program's whole capability
surface: `go` with a prefix of `test` still permits whatever flags `go test`
accepts. An entry whose executable is a shell or interpreter and whose prefix
is an eval flag (`sh -c`, `python -c`, and the like) matches arbitrary
commands, and Agenthof does not detect or reject those entries. Writing a
safe allowlist is the operator's obligation, the same way the sandbox is.

## Reporting the result

The agent `POST`s `/exec/attest` with
`{"command": ["go", "test", "./..."], "exit": 0, "output_sha": "<hex>"}`.
Agenthof answers `204` and appends one `exec` event:

| Field | What it holds |
| --- | --- |
| `command` | the argv the agent sent |
| `exit_code` | the exit status the agent sent, including `0` |
| `output_sha` | the hash the agent supplied. Agenthof does not see the output and does not compute this hash |
| `mode` | `attested` |
| `status` | `succeeded` when `exit` is `0`, otherwise `failed` |

The event also carries the run's delegation binding, like every other event
in the run. It does not carry the step's execution tier; that stays on the
step events.

Attest records what the agent reports. It does not match the argv against the
allowlist again. A conforming agent attests only a command it was allowed to
run. A non-conforming agent can report a command it never asked permission
for, and the ledger will show that report as succeeded or failed.

## What the record does and does not prove

The guarantee, stated plainly: *the agent, in its operator-provided sandbox,
reported running this command; Agenthof recorded but did not run or contain
it.*

- An allowed authorize writes nothing. A command that was allowed and never
  attested — the agent crashed between the two calls, or it never reported
  back — leaves no `exec` line. An investigator should not expect the number
  of authorize calls to equal the number of attest calls.
- A refused authorize is first-hand evidence that this door was asked and
  said no. It is not evidence about what the agent did next.
- Authorize is not a security control. A non-conforming agent can skip it
  and run whatever its sandbox allows. The sandbox is what confines
  execution. Authorize is prevention for a conforming agent, and a denial
  record when the request reaches the door.
- Attest is the agent's word, tagged `attested`. A buggy or compromised
  agent can report an exit code or an output hash that does not match what
  ran. The first-hand door below is the runtime's word, tagged `runtime`.
- The event joins the run's hash-chained ledger. What that chain does and
  does not prove is the same limit as every other event; see
  [`lifecycle.md`](lifecycle.md).

## The first-hand door

With `exec.mode: runtime` the agent does not run the command. It asks
Agenthof to, and a trusted operator-side runtime the operator declared —
`refexec`, in `deploy/refexec/`, a host process next to Agenthof — runs it
in its own rootless-podman compartment and attests to Agenthof what ran.
For the executable proof see
[`cmd/agenthof/testdata/script/door_exec_runtime.txtar`](../cmd/agenthof/testdata/script/door_exec_runtime.txtar);
for the runtime itself, [`deploy/refexec/README.md`](../deploy/refexec/README.md).

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

The agent declares it:

```yaml
exec:
  mode: runtime
  runtime: refexec
  url: unix:///run/agenthof-exec/refexec.sock
  timeout: 2m
  allow:
    - exe: cat
```

`runtime` names the trusted runtime (only `refexec` exists), `url` is its
Unix socket — a trusted runtime is reached only over a local socket, in a
directory only the user Agenthof runs as can enter — and `timeout` is the
deadline Agenthof puts on the whole call. All three are required with
`mode: runtime` and rejected with `mode: attested`; see
[`reference/config.md`](reference/config.md#exec).

The agent `POST`s `/exec/run` with `{"command": ["cat", "/work/agent-note.txt"]}`
and the run token. Agenthof, in order:

1. matches the argv against `allow`, the same rule as authorize. No match:
   an `exec` event with status `refused`, reason `command is not on the exec
   allowlist`, `mode: runtime`, and a `403`. refexec is never asked.
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

A body that is not JSON is answered `400` and records nothing, as on authorize.

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

The event:

| Field | What it holds |
| --- | --- |
| `command` | the argv Agenthof authorized (and verified refexec attested) |
| `exit_code` | the command's exit status, as refexec reports it |
| `output_sha` | refexec's SHA-256 of the output it returned; Agenthof recomputed it over what it received |
| `mode` | `runtime` |
| `status` | `succeeded` when the exit is `0`, `failed` otherwise — or `failed` with a `reason` when the door itself failed |
| `runtime_attestation` | refexec's first-hand account: `runtime: refexec`, `session` (the compartment's name, the key into refexec's own log), `command`, `pid` (the host pid of the `podman run` client refexec held — never a pid inside the compartment), `spawn: 1`, `env_names` (the variable names refexec injected), and empty `credential_env` / `materialization` (refexec is credential-less) |

The `exec` event carries `output_sha`, never the output itself. The output
goes back to the agent; what the agent does with it — for instance, return
it as the step's artifact — is recorded the way any step result is.

`audit` renders it as
`exec cat /work/agent-note.txt — exit 0 (runtime) [runtime-attested: refexec cat /work/agent-note.txt pid 4242 spawn 1]`,
on a failed exit too; a door failure renders as `exec … failed — <reason>`.

On a first-hand agent the two agent-asserted routes are closed: a `POST` to
`/exec/authorize` or `/exec/attest` is answered `403` and recorded as an
`exec` event with status `refused`, reason `exec on this agent is
first-hand: authorize and attest are not available`, and `mode: runtime` —
the agent cannot land its own report on a door a runtime serves.
Conversely `/exec/run` on an agent whose exec is `attested` (or who
declares none) is refused before the allowlist is consulted, with reason
`first-hand exec is not declared for this agent`, and recorded the same
way.

### The workspace

For a first-hand agent the workspace is a named podman volume, mounted
read-write at `/work` into the agent's refbox compartment
(`REFBOX_WORKSPACE_VOLUME` on the refbox recipe) and at refexec's
`workspace.path`, which must also be `/work`, into every refexec
compartment. Its life is the recipe's, not a run's: refexec's launcher
creates it, every run shares it, and the operator removes it
(`podman volume rm`) when tearing the recipe down — nothing removes it
automatically. One refbox, one refexec, one volume.
refbox starts before any run exists, so nothing can mint a volume per run.
Agenthof stays out of storage.

### What the first-hand record does and does not prove

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
- The event joins the run's hash-chained ledger, with the same limits as
  every other event; see [`lifecycle.md`](lifecycle.md).

## What ships today vs what is not a capability

| Shipped today | Not a capability |
| --- | --- |
| `mode: attested` — allowlist check on authorize, agent-reported outcome on attest, both on the per-run listener | Agenthof running the command itself — rejected at `apply`; exec containment is the operator's runtime's job, and Agenthof's job is to govern and record |
| `mode: runtime` — the allowlist check, then `refexec` runs the command first-hand in a no-network compartment and Agenthof records its account | a network allowlist for first-hand commands (they run with no network) |

Only shipped behavior is a guarantee.
