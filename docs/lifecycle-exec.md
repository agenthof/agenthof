# The life of an exec

One allowlisted command, from the moment a fronted agent asks permission to
the line the ledger keeps. This is the exec door. For the run it happens
inside, see [`lifecycle.md`](lifecycle.md). For the YAML, see
[`reference/config.md`](reference/config.md#exec). For the executable proof —
authorize, attest, and the rendered audit line — see the testscript
[`cmd/agenthof/testdata/script/door_exec.txtar`](../cmd/agenthof/testdata/script/door_exec.txtar).

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

Any agent may declare `exec`; every agent is fronted. The block names
`mode: attested` and a non-empty `allow` list. `enforced` — Agenthof running
the command itself — is reserved and rejected at `apply`. An `exec` block on
an agent whose `execution` is not `fronted` (including the removed value
`contained`) is rejected the same way.

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
  ran.
- The event joins the run's hash-chained ledger. What that chain does and
  does not prove is the same limit as every other event; see
  [`lifecycle.md`](lifecycle.md).

## What ships today vs what is reserved

| Shipped today | Reserved for later |
| --- | --- |
| `mode: attested` — allowlist check on authorize, agent-reported outcome on attest, both on the per-run listener | `mode: enforced` — Agenthof runs the command and records the outcome itself |

Only the attested door is a guarantee.
