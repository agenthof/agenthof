# `agenthof serve` — the control-plane API

`agenthof serve` is a long-lived process that hosts governed runs and
serves both ledgers back over HTTP. It is a control surface over the
same engine, gateway and doors `agenthof run` uses — nothing about how a
run is contained or recorded changes because it was triggered over the
network.

```
agenthof serve [--addr 127.0.0.1:8080] [--allow-non-loopback] [--addr-file <path>]
               [--config <dir>] [--log-dir <dir>] [--artifact-dir <dir>] [--control-log <path>]
               [--max-concurrent-runs <n>] [--shutdown-timeout <dur>]
               [--log-level debug|info|warn|error] [--log-format text|json]
```

`AGENTHOF_OIDC_ISSUER` is required (and `AGENTHOF_OIDC_CLIENT_ID`,
default `agenthof`; optionally `AGENTHOF_OIDC_AUDIENCE`). There is no
`--as` over the network: every call is authenticated with a real token.

## Authentication — every call, one token

Every request except `GET /healthz` carries `Authorization: Bearer
<token>`. The token is verified against the configured issuer on every
call, and the verified identity — subject, issuer, groups — is the
invoker the run is attributed to, exactly as with `run --token`. The
provider's discovery document and keys are fetched once for the
configured issuer and reused (a discovery that failed is not cached, so
the next call tries again); a token that names a different issuer is
simply rejected — the server never fetches anything a token tells it to.

A missing or invalid token gets `401` with the fixed body `unauthorized`
and nothing else: no run is created, nothing is written to any ledger,
no config is loaded. (The command-line `run --token` records a failed
token as a refused run; over the network that would let anyone fill the
log directory, so the API does not.) If the identity provider cannot be
reached, the answer is `503`.

## Endpoints

All bodies are JSON except `/audit`, which is plain text.

| Method and path | What it does |
|---|---|
| `POST /v1/runs` `{"role","workflow","input"}` | Starts a run. Answers `202` `{run_id, status:"running"}` with a `Location` header, or a **recorded refusal**: `403` `{run_id, status:"refused", reason}` when the role, workflow, ownership or groups say no (the same reasons `run` prints), `422` when the config directory does not validate. A refusal is a run: it has an id and a ledger. A body missing a field is `400` and a body over 1 MiB is `413`, neither of them a run. `429` with `Retry-After` when `--max-concurrent-runs` are in flight; `503` while shutting down. |
| `GET /v1/runs/{id}` | `{run_id, status, reason, started, finished, output_sha, output_preview}`. `status` is `running`, `succeeded`, `failed`, `refused`, `cancelled`, or `incomplete` (a ledger with no final event — the process ended before the run did). `reason` is the recorded reason for a refused, failed or cancelled run. Runs this process did not start are read from their ledger on disk. |
| `GET /v1/runs/{id}/events` | The run's ledger: `{events, head, integrity, broken_line}`. `integrity` is `verified`, `torn`, `broken` (with the 1-based `broken_line`), or `in_flight` — a record caught mid-write on a run still running here, which the next read will see whole. The verified prefix is always returned. |
| `GET /v1/runs/{id}/audit` | Exactly what `agenthof audit <id>` prints, rendered by the server — including the line that names the `apply` that put the run's config in place, which needs the control ledger the server has. The verdict also travels in the `Agenthof-Integrity` header so `audit --server` can exit as the local command does. |
| `GET /v1/runs` | `{runs: [{run_id, status}]}` — hosted runs and every run log on disk. |
| `GET /v1/investigate?since&until&invoker&agent&outcome&run&config_hash` | The `investigate/1` document over both ledgers; `since`/`until` are RFC3339. |
| `POST /v1/runs/{id}/cancel` | Cancels a run this process is hosting; `202`. **Any** authenticated invoker may cancel a run this process is hosting, not only the one who started it. The engine records `cancelled` at or after the current step. A run this process does not host is `404` (there is nothing to cancel), one that is already over is `409`. |
| `GET /healthz` | Liveness, unauthenticated, `ok`. Nothing else. |

Run ids are validated before anything touches the filesystem.

## The CLI as a client

`run`, `audit <id>` and `investigate` take `--server <url>` (or
`AGENTHOF_SERVER`) with `--token` (or `AGENTHOF_TOKEN`) and print
exactly what they print locally: `run` waits for the run to finish,
`audit` prints the server's rendering, `investigate` prints the text or
`--json` document. `apply` and `registry` stay local.

## Where a run came from: `origin`

A run started over the API records an `origin` on its `workflow_started`
(or `run_refused`) event: `via: "api"`, the remote address, the
`User-Agent`, the server's address, and `forwarded_for` copied verbatim
from `X-Forwarded-For`. This is **provenance, not identity**: the
verified token says *who*; `origin` says *which way in*. `forwarded_for`
is whatever the request carried and is **not verified** — a proxy can
set it, so can anyone else. Each field is capped at 200 characters and
stripped of non-printable characters before it is written. Runs started
from the command line carry no `origin`; their events are unchanged. A
run spawned by a served run inherits its parent's `origin`.

## Who may read

Any authenticated invoker may read any run: the audit trail is a floor,
not a privilege. Be aware of what that exposes to another authenticated
user: a run's `output_preview` and step previews, the reasons adapters
and doors recorded (which may quote an upstream's answer), and in
`investigate` the server-side paths of the ledgers read. A finer
read/audit permission is a planned addition, not a current one.

## Binding and TLS

The default bind is `127.0.0.1:8080`. Serving any other address
requires `--allow-non-loopback`, and the server speaks plain HTTP: put
TLS in front of it (a reverse proxy, a service mesh, a tunnel). Client
certificates as a second corroborator of origin are reserved.
`--addr-file` writes the bound `host:port` after listening, for a `:0`
port; the file is not removed when the process exits, so treat a stale
one as what it is — a leftover, not a running server.

## Concurrency and shutdown

`--max-concurrent-runs` (default 8) bounds runs in flight; the slot is
taken before the request body is read or the config loaded, so a caller
cannot make the server load config outside the cap. On `SIGINT`/`SIGTERM`
the server stops accepting runs (`POST /v1/runs` answers `503`), keeps
answering reads, cancels every in-flight run and waits up to
`--shutdown-timeout` (default: the config's step timeout) before
closing. A deadline shorter than the step timeout can cut a run off
mid-step; its ledger then has no final event and reads back as
`incomplete`.

## Honest limits

- The config directory is read per run; `apply` validates it but does
  not install it, so a served run executes whatever the directory holds.
- The invoker's token is also the subject token for on-behalf-of tool
  calls; a run longer than the token's lifetime can fail such a call
  mid-run. There is no refresh.
- Cancellation is recorded at or after the current step; work inside the
  step may finish or hit its timeout first.
- Runs are read cross-invoker (above).
- On `/audit` the header and the text can disagree while a run is still
  being written: the `Agenthof-Integrity` header reports `in_flight`,
  the rendered text still says `TORN — last record incomplete`, because
  it is the same rendering the local command produces and the local
  command has no notion of a run in flight. Neither reading is damage;
  read the chain again once the run is over.
- The table of hosted runs is kept for the life of the process.
- Streaming (`?follow=1`) is not offered; poll `GET /v1/runs/{id}` or
  read `/events`.
