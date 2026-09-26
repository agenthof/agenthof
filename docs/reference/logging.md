# Operational logging

Agenthof speaks on three channels, and they never mix:

| Channel | What it carries | Where it goes | Flag |
|---|---|---|---|
| Results | what a command produced (`run r-… finished: succeeded`, audit renderings, `investigate` output) | **stdout** | — |
| Run ledger | the audit record: one hash-chained event per governed action | **`<log-dir>/<run-id>.jsonl`** | `--log-dir` |
| Operational log | diagnostics for whoever runs the process: listener start/stop, upstream failures, retries | **stderr** | `--log-level`, `--log-format` |

`--log-dir` names the **run ledger** directory (the audit record `agenthof
audit` and `agenthof investigate` read). `--log-level` and `--log-format`
configure the **operational log** on stderr. The names are close; the streams
are not: the ledger is the evidence, the operational log is the running
commentary, and stdout is the answer.

## Flags

Both flags live on `agenthof run`. Each has an environment fallback; a flag,
when given, wins over its variable.

| Flag | Values | Default | Environment |
|---|---|---|---|
| `--log-level` | `debug`, `info`, `warn`, `error` | `info` | `AGENTHOF_LOG_LEVEL` |
| `--log-format` | `text`, `json` | `text` | `AGENTHOF_LOG_FORMAT` |

An unrecognised value is a usage error: it is reported on stdout with exit
code 2, like every other usage error. Only `agenthof run` emits operational
logs today; the other subcommands print their results and stop.

```sh
agenthof run se wf --input "…" --log-level debug --log-format json 2> agenthof.log
AGENTHOF_LOG_LEVEL=warn agenthof run se wf --input "…"
```

## Levels

| Level | Examples |
|---|---|
| `error` | a per-run listener failed to bind; an upstream MCP resource could not be connected or listed; a model call did not complete; a ledger or artifact-store write failed |
| `warn` | a step failed and bounced back; a tool call was refused or reported an error; a model upstream answered with an error status; a run was refused |
| `info` | the per-run gateway listener started and stopped |
| `debug` | run and step lifecycle; which tools were mirrored for a step; each tool and model call routed |

Run start and finish are `debug`, not `info`: stdout already prints the result
line, and repeating it on stderr at the default level would be noise.

## Fields

Engine lines carry `run` (the run id), `role`, and `workflow`. The gateway
scopes its lines with `run` and `agent`; tool lines add `resource` and `tool`;
model lines add `model` (the logical name, never the provider's). A transport
failure carries a `class` (`timeout`, `connection_refused`, `dns`, `canceled`,
`other`) rather than the error's text.

## What is never logged

The operational log is held to the same line as the ledger: no injected
provider key, no resource credential, no minted upstream token, no per-run
token, no `Authorization` header value, no artifact body, and no upstream URL
(a URL can carry a secret in its query string). A transport error is reduced
to a fixed message plus its class for that reason. This is pinned by a test
that captures the log at `debug`, in both formats, across the success and
failure branches of the model, tool, and exec doors, and asserts that no
secret appears raw, Base64-encoded as a Basic credential, or as a prefix.

## Using Agenthof as a library

`engine.Run` takes an optional `*slog.Logger` in its options and
`rungateway.New` takes one as a parameter; a nil logger discards everything.
The handler inside that logger is the seam: a binary that wires the engine
and gateway itself can hand them a logger built on any `slog.Handler` — a
fan-out, an exporter bridge — with no other change. The stock `agenthof` CLI
offers only the stdlib text and JSON handlers on stderr.
