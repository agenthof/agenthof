# `agenthof serve` — the control-plane API

`agenthof serve` is a long-lived process that hosts governed runs and
serves both ledgers back over HTTP. It is a control surface over the
same engine, gateway and doors `agenthof run` uses — nothing about how a
run is contained or recorded changes because it was triggered over the
network.

```
agenthof serve [--addr 127.0.0.1:8080] [--allow-non-loopback] [--allow-api-bootstrap] [--addr-file <path>]
               [--config <dir>] [--log-dir <dir>] [--artifact-dir <dir>] [--control-log <path>]
               [--max-concurrent-runs <n>] [--shutdown-timeout <dur>]
               [--log-level debug|info|warn|error] [--log-format text|json]
```

`--config` is accepted for compatibility and read by nothing: runs execute the
installed configuration beside `--control-log`.

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
| `POST /v1/runs` `{"role","workflow","input"}` | Starts a run. Answers `202` `{run_id, status:"running"}` with a `Location` header, or a **recorded refusal**: `403` `{run_id, status:"refused", reason}` when the role, workflow, ownership or groups say no (the same reasons `run` prints), `422` when nothing is installed under the control root (`reason: no configuration installed`) or the installed configuration does not validate. A refusal is a run: it has an id and a ledger. A body missing a field is `400` and a body over 1 MiB is `413`, neither of them a run. `429` with `Retry-After` when `--max-concurrent-runs` are in flight; `503` while shutting down. |
| `GET /v1/runs/{id}` | `{run_id, status, reason, started, finished, output_sha, output_preview}`. `status` is `running`, `succeeded`, `failed`, `refused`, `cancelled`, or `incomplete` (a ledger with no final event — the process ended before the run did). `reason` is the recorded reason for a refused, failed or cancelled run. Runs this process did not start are read from their ledger on disk. |
| `GET /v1/runs/{id}/events` | The run's ledger: `{events, head, integrity, broken_line}`. `integrity` is `verified`, `torn`, `broken` (with the 1-based `broken_line`), or `in_flight` — a record caught mid-write on a run that is still running here, which the next read will see whole. The verified prefix is always returned. |
| `GET /v1/runs/{id}/audit` | Exactly what `agenthof audit <id>` prints, rendered by the server — including the line that names the install that put the run's config in place, which needs the control ledger the server has. The verdict also travels in the `Agenthof-Integrity` header so `audit --server` can exit as the local command does. |
| `GET /v1/runs` | `{runs: [{run_id, status}]}` — hosted runs and every run log on disk. |
| `GET /v1/investigate?since&until&invoker&agent&outcome&run&config_hash` | The `investigate/1` document over both ledgers; `since`/`until` are RFC3339. |
| `POST /v1/runs/{id}/cancel` | Cancels a run this process is hosting; `202`. **Any** authenticated invoker may cancel a run this process is hosting, not only the one who started it. The engine records `cancelled` at or after the current step. A run this process does not host is `404` (there is nothing to cancel), one that is already over is `409`. |
| `POST /v1/config/apply` `{"files": {"roles/ops.yaml": "<yaml>", …}}` with `If-Match: sha256:<hex>` or `If-None-Match: *` | Applies a configuration — the same `apply` the command line runs, over the server's control root. The body is the configuration's files by config-relative path (`agents/`, `workflows/`, `roles/`, `gateway.yaml`), as text, at most 1 MiB and 1000 files. Exactly one precondition header is required: `If-Match` names the installed configuration's hash the caller believes is current; `If-None-Match: *` means "only if nothing is installed" (a bootstrap, permitted only with `--allow-api-bootstrap`). Answers `200` `{status:"installed", config_hash, bootstrap, head, agents, workflows, roles}` with an `ETag` — a **recorded** `success`; `403` `{status:"refused", reason, config_hash, head}` — a **recorded** refusal when the installed configuration's roles grant the caller no `apply` (or nothing is installed and bootstrap is off); `422` `{status:"rejected", reason, errors, config_hash, head}` — a **recorded** rejection with every load and validation line; `412` `{status:"precondition_failed", current_hash}` (and an `ETag`) when the pointer is not what `If-Match` said — nothing recorded, retry with `current_hash`; `409` `{status:"busy"}` with `Retry-After` while another apply holds the writer lock — nothing recorded. A malformed body or key is `400`, over the cap `413`, neither recorded. `500` carries `{status:"error", reason:"store unusable"}` (a **recorded** `error`), `{status:"ledger_damaged"}` (nothing can be recorded) or `{status:"installed_not_recorded"}` (the install landed, its record did not); the server never returns its own paths. `503` while shutting down. |
| `GET /healthz` | Liveness, unauthenticated, `ok`. Nothing else. |

Run ids are validated before anything touches the filesystem.

## The CLI as a client

`run`, `audit <id>`, `investigate` and `apply` take `--server <url>` (or
`AGENTHOF_SERVER`) with `--token` (or `AGENTHOF_TOKEN`) and print what
they print locally: `run` waits for the run to finish, `audit` prints the
server's rendering, `investigate` prints the text or `--json` document,
and `apply --server --if-installed <sha256:hex|none>` sends the
configuration (`--config`, read exactly as a local apply would snapshot
it, or `--bundle <file|->`, the request body itself) and prints the local
lines plus `installed: sha256:<hex>` — the hash the next `--if-installed`
names. `registry enable|disable` and `audit repair control` stay local.

## Where a change came from: `origin`

A run started over the API records an `origin` on its `workflow_started`
(or `run_refused`) event, and a configuration applied over the API records
the same `origin` on its control event: `via: "api"`, the remote address,
the `User-Agent`, the server's address, and `forwarded_for` copied
verbatim from `X-Forwarded-For`. This is **provenance, not identity**:
the verified token says *who*; `origin` says *which way in*.
`forwarded_for` is whatever the request carried and is **not verified** —
a proxy can set it, so can anyone else. Each field is capped at 200
characters and stripped of non-printable characters before it is written.
Runs and applies from the command line carry no `origin`; their records
are unchanged. A run spawned by a served run inherits its parent's
`origin`. On an API-recorded control event the `witness` — the OS user
and hostname that wrote the record — is the **server's**, and
corroborates nothing about the caller; `audit control` renders such a
line as `dana@example.com (oidc, via api)`.

## Applying configuration over the API

`POST /v1/config/apply` is the one write to the control plane the API
offers, and it is the same `apply`: the verified token is the invoker; it
is authorized against the `control:` grants of the configuration already
**installed** (never the one being proposed); the proposal is staged,
loaded, validated and installed as a content-addressed snapshot; the
outcome is recorded in the hash-chained control ledger with its `origin`;
and the next `POST /v1/runs` executes it — no restart.

**The precondition is required.** Two operators who cannot see each
other's filesystem need a compare-and-swap, not a convention. `If-Match:
sha256:<hex>` says "replace the installed configuration, which I believe
is this one"; `If-None-Match: *` says "install only if nothing is
installed". A mismatch is `412` with the current hash and is **not**
recorded — no decision was made, and the hash is the snapshot's public
name (any authenticated invoker can read it from `/v1/investigate`
already). Re-applying the bytes that are already installed with the
correct `If-Match` records a `success` and changes nothing; a retry of a
`200` that was lost in transit reads back as `412`, and `apply --server`
says so.

**One writer at a time.** Every writer of the installed pointer — an API
apply, a command-line apply on the same host, and the kill switch — takes
one lock beside the store (`installed.lock`) from the moment it reads the
installed roles until its record is appended, so the roles that
authorized a change are the roles of the configuration it replaces. A
second API apply is answered `409` at once; a command-line writer makes
an API apply wait up to five seconds, then `409`. Nothing queues.

**Bootstrap is opt-in.** With nothing installed, a command-line apply is
permitted for any caller — that caller already owns the filesystem. Over
the network that reasoning fails: a fresh server would make the first
token-holder the configuration's owner. So an API apply while nothing is
installed is a recorded refusal unless the server runs with
`--allow-api-bootstrap`; enable it on a loopback server for a first
install, or apply locally first.

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
the server stops accepting runs and applies (`POST /v1/runs` and `POST
/v1/config/apply` answer `503`), keeps answering reads, cancels every
in-flight run, waits for an apply in flight, and waits up to
`--shutdown-timeout` (default: the config's step timeout) before
closing. A deadline shorter than the step timeout can cut a run off
mid-step; its ledger then has no final event and reads back as
`incomplete`.

## Honest limits

- The installed configuration is read per run: an `apply` or kill-switch
  flip takes effect on the next run, with no restart; with nothing installed
  every run is refused (422) until an `apply` lands — `serve` starts
  regardless. The shutdown deadline's default is read once at startup, so a
  server started with nothing installed keeps the default step timeout as its
  drain deadline after a later apply; `--shutdown-timeout` sets it explicitly.
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
- A run cancelled in the brief window between steps while its gateway is
  starting is recorded as `failed` (the gateway start failing), not
  `cancelled` — a narrow residual; the common case (cancel during a step)
  records `cancelled`.
- `GET /v1/runs` and `/v1/investigate` read and verify every ledger under
  the log directory on each call, and are not paginated; both are fine at a
  single host's scale and are where aggregation/pagination will land later.
- While the identity provider is unreachable, token verification waits on
  the discovery timeout and requests serialize behind it; a negative
  cache / backoff is reserved.
- The witness on an API-recorded control event is the server's OS user and
  hostname; `origin` is unverified provenance; the token is the who.
- There is no way to remove the installed pointer over the API — by design.
  A configuration that grants `apply` to a group no token carries locks
  every network caller out; the only way back is the host's filesystem.
- Bootstrap over the API is off unless `--allow-api-bootstrap`; on, the
  first authenticated caller installs the first configuration, recorded
  `bootstrap:true` with `via:"api"`.
- The drain deadline can still end the process after an apply installed
  its snapshot and before its record was appended — an apply parked behind
  a command-line writer can outlast a short `--shutdown-timeout`. `audit
  verify control` then exits 5 (pointer without a record), the same
  surface as a run cut off mid-step.
- `409` is not a queue: nothing waits on the server's behalf beyond the
  five-second lock retry; the client retries.
- `412` discloses the installed hash to any authorized caller; `422`
  returns every load and validation line (config-relative names only) to
  the caller who proposed the bytes.
- Writers are serialized per host. A store on a network filesystem shared
  by several hosts is outside what the lock promises — the ledger's own
  lock carries the same caveat.
- A bundle whose file names are not plain ASCII can be refused on a store
  that normalizes names (HFS+ stores NFD): the staged copy no longer
  hashes as the proposal, and the apply is recorded as an error with
  nothing installed. APFS and ext4 preserve names and are unaffected.
- `apply` is the only control command over the API; `registry
  enable|disable`, `audit repair control`, and `audit control` stay local.
