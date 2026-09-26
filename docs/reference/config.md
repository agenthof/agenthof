# Configuration reference

This is the field-by-field reference for the YAML config Agenthof loads and
validates. Every field name and semantic statement in the sections below,
up to [Control-plane CLI](#control-plane-cli), is drawn from two files, and
only those two: the struct comments in
[`internal/config/types.go`](../../internal/config/types.go) (what a field
means and its default) and the rules in
[`internal/registry/validate.go`](../../internal/registry/validate.go) (what
`agenthof apply` accepts or rejects). Behavior that lives elsewhere — how the
engine executes a workflow, how identity and the ledger work, how an
agent runs — is covered in [`docs/concepts.md`](../concepts.md),
not repeated here. The [Control-plane CLI](#control-plane-cli) section is
the one exception: it documents command-line flags and exit codes, drawn
from [`cmd/agenthof/main.go`](../../cmd/agenthof/main.go) — these commands
govern config, so their invocation is documented alongside it, while what
they record and why is covered in
[`docs/concepts.md`](../concepts.md#control-plane-audit).

Examples marked "from `examples/config/`" are real files that pass `apply`
(see the [quickstart](../quickstart.md)). Examples marked "illustrative" are
not present in `examples/config/` — they exist to show a rule from
`validate.go` that the shipped examples don't exercise.

## Agents (`config/agents/*.yaml` → `AgentDef`)

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Name | `name` | string | yes | — |
| Description | `description` | string | no | — |
| Enabled | `enabled` | bool | no | `true` |
| Model | `model` | string | no | — |
| Instruction | `instruction` | string | no | — |
| Tools | `tools` | list of tool grants (a resource id, or a {resource, tools} object) | no | none |
| Output | `output` | string | no | — |
| Execution | `execution` | string | no | `fronted` |
| Endpoint | `endpoint` | string | yes | — |
| Exec | `exec` | object | no | none |

### `name`

Required. `apply` rejects an agent with no name (`missing-name`) and rejects
a second agent reusing a name already defined (`duplicate-name`).

### `description`

Optional, free text. Not checked by `apply`.

### `enabled`

Optional bool. Per the comment on `AgentDef.Enabled`, `enabled: null` (i.e.
the key is omitted, or set to `null`) means **enabled** — `nil` means `true`.
A workflow step whose agent resolves to a disabled agent fails `apply` with
`disabled-agent-ref`.

### `model`

Optional string. The agent's effective model is this value, or
`gateway.yaml`'s `defaults.model` when it is empty. `apply` does not check
that the name has a route. At run time the model door allows a chat
completion only when the agent's request names that effective model, then
resolves it through [`models`](#models).

### `instruction`

Optional free text. Not checked by `apply`.

### `tools`

Optional list of tool grants. Each entry is either the id of a tool
resource declared under `gateway.yaml`'s `tools` map (see
[`tools`](#tools-1) under Gateway, below), which grants every tool that
resource exposes, or an object with two keys:

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Resource | `resource` | string | yes | — |
| Tools | `tools` | list of strings | yes, non-empty | — |

which grants only the named tools of that resource. The bare string is the
only way to grant every tool: an object whose `tools` is missing, `null`, or
empty is rejected when the file is loaded, as is an object with any key
other than `resource` and `tools`, or with an empty `resource` — all with
`bad-tool-grant` — so a misspelled key can never widen a grant.

`apply` rejects an entry whose resource is not declared in `gateway.yaml`
with `unknown-tool` ("agent references tool ..., which is not a declared
gateway tool resource"), an empty tool name with `bad-tool-grant`, and a
resource that appears in more than one entry when any of those entries is
the object form — also `bad-tool-grant` ("resource ... is granted more than
once and at least one of those grants restricts tools; merge them into one
grant"). A resource repeated only as bare ids is accepted, as before. `apply`
does not check tool names against the resource itself; a name the resource
does not expose fails the step at run time instead. The agent reaches its
granted tools only through Agenthof's inbound MCP proxy for the duration of
its step — see [`lifecycle-tool.md`](../lifecycle-tool.md) for the runtime
flow; this reference only covers what `apply` checks.

### `output`

Optional string. Not checked by `apply`.

### `execution`

Optional string; per the comment on `AgentDef.Execution`, the accepted
values are `""` or `"fronted"`, and `""` means `fronted` (see
`AgentDef.EffectiveExecution`). `apply` rejects `"contained"` with
`bad-execution` ("execution \"contained\" was removed; set execution:
fronted and an endpoint"). Any other value is rejected with `bad-execution`
("execution ... must be \"fronted\"").

### `endpoint`

Required; per the comment on `AgentDef.Endpoint`, "the agent's HTTP
endpoint". `apply` rejects an empty endpoint with `fronted-needs-endpoint`.
The message is "agents are fronted and must declare an endpoint (the
contained tier was removed)" when `execution` is empty, and "fronted agents
must have an endpoint" when `execution` is `fronted`. A non-empty endpoint
must be `https`, `http` whose host is `localhost`, `127.0.0.1`, or `::1`, or
a `unix://` socket path (the path after `unix://` must be absolute; it names
only the socket, not an HTTP route). Anything else is rejected with
`bad-endpoint` ("endpoint must be https, loopback http, or unix:// socket").
A `unix://` value is accepted only here. Tool and token endpoints stay on the
stricter https-or-loopback rule, because those calls carry a remote credential.

Every fronted step receives `X-Agenthof-Proxy-URL` and
`X-Agenthof-Run-Token`, whether or not the agent declares `tools` or `exec`.
The model door is `POST <proxy URL>v1/chat/completions` with that run token.
An agent uses the doors it needs and ignores the rest. See
[`lifecycle-model.md`](../lifecycle-model.md).

### `exec`

Optional, and only on a `fronted` agent. Declares commands the agent may
report running in the operator's sandbox. Agenthof checks the reported argv
against `allow` and records the result. It does not run the command and does
not contain it. The operator's sandbox is what confines execution.

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Mode | `mode` | string | yes when `exec` is set | — |
| Allow | `allow` | list of objects | yes, non-empty, when `mode` is set | — |

`mode` accepts only `attested`. `enforced` (Agenthof running the command) is
**not a planned capability** and is rejected at `apply` with `bad-exec-config`;
the field keeps the two-value shape as a seam, but first-hand exec is at most a
future commercial add-on, not core. Any other value,
including an empty `mode` on a block that still lists `allow`, is rejected
the same way.

Each `allow` entry:

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Exe | `exe` | string | yes | — |
| ArgsPrefix | `args_prefix` | list of strings | no | empty (any arguments) |

A reported argv matches an entry when `argv[0]` equals `exe` exactly (no
glob) and `args_prefix` is a prefix of the arguments that follow. The rest of
the argv is unconstrained. An empty `args_prefix` matches any invocation of
that `exe`. An argv shorter than the prefix does not match.

`apply` rejects, all with `bad-exec-config`:

- `exec` on an agent whose effective execution is not `fronted`;
- `mode` set to anything other than `attested`;
- `mode` set with an empty `allow`;
- an `allow` entry whose `exe` is empty.

Allowlisting an executable trusts that program's whole capability surface.
`exe: go` with `args_prefix: [test]` still permits `go test` with whatever
flags that program accepts. An entry whose `exe` is a shell or interpreter
and whose prefix is an eval flag (`sh -c`, `python -c`, and the like) makes
the allowlist match arbitrary commands while the ledger still records them as
allowlisted. Agenthof does not detect or reject those entries. Writing a
safe allowlist is the operator's obligation, the same way the sandbox is.

**Example:**

```yaml
name: builder
execution: fronted
endpoint: https://builder.internal/run
exec:
  mode: attested
  allow:
    - exe: go
      args_prefix: [test]
    - exe: rg
```

**Example (from `examples/config/agents/planner.yaml`):**

```yaml
name: planner
description: Turns a task into a short numbered plan
model: fast
instruction: |
  You are a planning agent. Produce a short numbered plan for the task.
output: plan
execution: fronted
endpoint: http://127.0.0.1:8080/
```

**Example (illustrative, with declared tools):**

```yaml
name: legacy-triage
description: Fronts an existing HTTP agent behind the registry
execution: fronted
endpoint: https://legacy.internal/agents/triage
tools:
  - ticket-search                        # every tool ticket-search exposes
  - resource: billing-mcp
    tools: [get_invoice, list_invoices]  # only these two of billing-mcp
# `model` is not checked. Each entry must name a resource under
# gateway.yaml's `tools` map (see `ticket-search` and `billing-mcp` in the
# Gateway examples below), or apply rejects the agent with unknown-tool.
```

## Workflows (`config/workflows/*.yaml` → `WorkflowDef` / `Step`)

`WorkflowDef` fields:

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Name | `name` | string | yes | — |
| Description | `description` | string | no | — |
| Steps | `steps` | list of `Step` | yes (non-empty) | — |

`Step` fields:

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Name | `name` | string | no (not checked by `apply`; used as the target for `on_success`/`on_failure`) | — |
| Agent | `agent` | string | yes | — |
| OnSuccess | `on_success` | string | no | next step (`finish` on the last step) |
| OnFailure | `on_failure` | string | no | previous step |
| MaxBounces | `max_bounces` | int | no | `2` |

### `name` (workflow) / `description` (workflow)

`name` is required: a workflow with no name is rejected with `missing-name`,
and a second workflow reusing a name is rejected with `duplicate-name`.
`description` is optional free text, not checked by `apply`.

### `steps`

Required to be non-empty: a workflow with zero steps is rejected with
`no-steps`.

### `name` (step) / `agent`

Each step names the agent that executes it. `apply` rejects a step whose
`agent` does not match any defined agent name with `dangling-agent-ref`, and
rejects a step whose agent exists but is disabled (see `enabled` above) with
`disabled-agent-ref`. An omitted `agent` is itself a name that matches no
agent, so it is also caught by `dangling-agent-ref`.

### `on_success`

Per the comment on `Step.OnSuccess`: `""` means "next step, or `\"finish\"`
on last". `apply` accepts an explicit `on_success` only when it is exactly
the name of the following step, or when it is the literal `"finish"` and the
step is the last one in the workflow; anything else is rejected with
`bad-graph` ("on_success must be the next step (or \"finish\" on the last
step); branching is not yet supported").

### `on_failure`

Per the comment on `Step.OnFailure`: `""` means "previous step (\"fail\" if
first)" — i.e. on the first step there is no previous step to bounce back
to, so an empty `on_failure` there means the run fails. When `on_failure` is
set explicitly, `apply` requires it to name a step strictly earlier in the
list; an unknown name or a step at or after the current one is rejected with
`bad-graph` ("on_failure must name an earlier step; forward or unknown
targets are not supported"). `"fail"` is not itself a recognized
`on_failure` value — it is the described *outcome* of leaving the field
empty on the first step, not a literal you write in YAML.

### `max_bounces`

Per the comment on `Step.MaxBounces`: `0` means the default of `2`. `apply`
rejects any value outside `0`–`10` with `bad-bounces` ("max_bounces must be
between 0 and 10").

**Example (from `examples/config/workflows/fix-bug.yaml`):**

```yaml
name: fix-bug
description: Take a bug report from plan to reviewed patch
steps:
  - name: plan
    agent: planner
  - name: code
    agent: coder
    on_failure: plan
  - name: review
    agent: reviewer
    on_failure: code
    max_bounces: 2
```

## Roles (`config/roles/*.yaml` → `RoleDef`)

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Name | `name` | string | yes | — |
| Description | `description` | string | no | — |
| Workflows | `workflows` | list of strings | yes (non-empty) | — |
| AllowedGroups | `allowed_groups` | list of strings | yes (non-empty) | — |
| BudgetUSDMonth | `budget_usd_month` | float | no | — |

### `name` / `description`

`name` is required: a role with no name is rejected with `missing-name`, and
a second role reusing a name is rejected with `duplicate-name`.
`description` is optional free text, not checked by `apply`.

### `workflows`

Required to be non-empty: a role owning zero workflows is rejected with
`no-workflows`. Every name in the list must match a defined workflow, or
`apply` rejects it with `dangling-workflow-ref`.

### `allowed_groups`

Required, non-empty list of strings. Authorization is **default-deny**: a
role with no `allowed_groups` — the key omitted, or present but empty — is
rejected by `apply` with `no-access-floor` ("role has no allowed_groups;
list real groups or `["*"]` to declare it public"). There is no config that
grants access by omission. To open a role to any authenticated invoker,
list the literal string `"*"` as its own entry — `allowed_groups: ["*"]` —
the explicit marker for "public"; anything else in the list is treated as a
real group name and `apply` does not otherwise check group names against an
external source (see [`docs/concepts.md`](../concepts.md) for how identity
and groups are used outside of `apply`).

### `budget_usd_month`

Optional float. `apply` does not check its value. `gateway provision` sends
it to the upstream gateway as that role's budget and writes the resulting
key under `.agenthof/keys/<role>.key` in the working directory. A run that
finds the key injects it on model calls, so the upstream gateway enforces
the budget (HTTP 429, recorded as a refused `model_call` with reason
`budget`). Agenthof does not itself cap spend. With no key file, model
calls use the route's `api_key_env` and no budget applies. See
[`models`](#models).

**Example (from `examples/config/roles/accountant.yaml`):**

```yaml
name: accountant
description: Financial operations and reconciliation
workflows: [reconcile-lite]
allowed_groups: [finance]
budget_usd_month: 20
```

## Gateway (`config/gateway.yaml` → `GatewayConfig` / `ModelRoute` / `ToolResource`)

`GatewayConfig` fields:

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Models | `models` | map of string → `ModelRoute` | no | — |
| Tools | `tools` | map of string → `ToolResource` | no | — |
| Defaults.Model | `defaults.model` | string | no | — |
| RefboxSocketDir | `refbox_socket_dir` | string | no | empty (TCP loopback) |

`ModelRoute` fields:

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Endpoint | `endpoint` | string | no (not checked by `apply`) | — |
| Model | `model` | string | no (not checked by `apply`) | — |
| APIKeyEnv | `api_key_env` | string | no (not checked by `apply`) | — |

`ToolResource` fields — a declared tool/MCP resource, reached through
Agenthof's inbound MCP proxy by any agent that lists its id under
`tools` (see [`tools`](#tools) under Agents, above, and
[`docs/lifecycle.md`](../lifecycle.md#how-an-agent-actually-runs)
for the runtime flow):

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Kind | `kind` | string | yes | — |
| URL | `url` | string | yes; must be `https`, or `http` to a loopback host | — |
| CredentialSource | `credential_source` | string | yes | — |
| TokenEnv | `token_env` | string | yes for the direct-bearer grant (`grant_type: ""`) | — |
| GrantType | `grant_type` | string | no | `""` (direct-bearer) |
| ClientAuth | `client_auth` | string | yes for `client_credentials` (must be `client_secret_basic`) | — |
| Issuer | `issuer` | string | yes for `client_credentials` | — |
| TokenEndpoint | `token_endpoint` | string | yes for `client_credentials`; must be `https`, or `http` to a loopback host | — |
| ClientIDEnv | `client_id_env` | string | yes for `client_credentials` | — |
| ClientSecretEnv | `client_secret_env` | string | yes for `client_credentials` | — |
| Scope | `scope` | string | no (not checked by `apply`) | — |

`apply` requires `kind` to be exactly `"mcp"` and `url` to be set and
`https` (or `http` only to a loopback host — `localhost`, `127.0.0.1`, or
`::1`). The gateway injects a credential on every call to that url, so a
plaintext url on a remote host is rejected at apply time, the same rule as
`token_endpoint`. A resource that fails either check is rejected with
`bad-tool-resource` ("tool resource ... must set kind: mcp", or "url must be
set and https (or loopback http)"). `apply` separately requires
`credential_source` to be exactly `"static_env"`, rejecting anything else
(including empty) with `bad-tool-resource` ("credential_source ... is not
implemented (only static_env)"). `apply` also validates `grant_type`: the
empty value is the direct-bearer grant and requires `token_env` (read at the
moment a fronted step starts, when the proxy resolves the named environment
variable to a credential; naming a variable that isn't set fails that step,
not `apply`, with a broker error); `"client_credentials"` requires
`client_auth` to be exactly `"client_secret_basic"`, plus `issuer`,
`token_endpoint`, `client_id_env`, and `client_secret_env` all set, with
`token_endpoint` required to be `https` (or `http` only to a loopback host —
a client secret over plaintext http to a remote host is rejected at apply
time); any other `grant_type` is rejected as not implemented. `scope` is
optional and not validated or required by `apply`; when set on a
`client_credentials` resource, the broker forwards it verbatim, as a single
space-delimited string, in the token request's `scope` parameter (empty
means the request omits `scope` entirely and the authorization server's own
default applies). `TokenEnv`,
`ClientIDEnv`, and `ClientSecretEnv` hold the *name* of an environment
variable, never a credential value.

### `models`

A map from a logical model name to a `ModelRoute`. `apply` accepts the map
and does not validate its keys or the contents of each entry (`endpoint`,
`model`, `api_key_env`). The model door reads it on each chat completion.

The agent sends the logical name. Agenthof rewrites the outbound `model` to
the route's `model` and sends the call to the route's `endpoint`
(`POST /v1/chat/completions`). The key is the role's provisioned key when
`.agenthof/keys/<role>.key` exists in the working directory — the same
directory `gateway provision` writes — and otherwise the value of
`api_key_env`. The run token is not forwarded. See
[`lifecycle-model.md`](../lifecycle-model.md).

### `tools`

A map from a tool-resource id to a `ToolResource` (fields above). An agent's
`tools` list (see [`tools`](#tools) under Agents) names ids from this map,
bare or inside a `{resource, tools}` object; `apply` rejects an agent entry
that doesn't resolve here with `unknown-tool`, and validates every declared
resource itself against the `ToolResource` rules above (`bad-tool-resource`).
At runtime, a step whose agent declares tools reaches them only through
Agenthof's inbound MCP proxy, never directly — see
[`lifecycle-tool.md`](../lifecycle-tool.md).

### `refbox_socket_dir`

Optional string. Empty — the default — leaves the per-run gateway on a TCP
loopback port, and the proxy URL stays `http://127.0.0.1:<port>/`. When set,
each fronted step's gateway listens on a Unix domain socket in this directory
instead, and the proxy URL is `unix://` plus that socket's path. The value
after `unix://` is the socket path only; the HTTP routes stay fixed (`/`,
`/exec/authorize`, `/exec/attest`, `/v1/chat/completions`). The run token
still travels in the `Authorization` header. `apply` does not check that the
directory exists. Keep the directory's path short: a Unix socket path has a
small operating-system length limit, and a path that exceeds it fails the
step at listen time.

`deploy/refbox/` is a reference recipe. Its socket directory defaults to
`$XDG_RUNTIME_DIR/agenthof` (user-owned, so a rootless `mkdir` works; `/run`
itself is root-owned). Set `refbox_socket_dir` to that same directory, and
set the agent `endpoint` to `unix://` plus that directory plus
`/refbox-echo.sock`. The adapter dials the endpoint; the recipe's `-socket`
flag only chooses where the compartment listens. The checked-in demo config
uses `/run/agenthof` as a placeholder, because YAML cannot expand
`$XDG_RUNTIME_DIR`. The two paths must match. See
[the life of a run](../lifecycle.md#a-reference-compartment-refbox).

### `defaults` / `defaults.model`

`defaults` is a nested object holding one field, `model` (optional string).
`apply` does not read it. The model door uses it as the effective model for
an agent that leaves `model` empty (see [`model`](#model)).

**Example (from `examples/config/gateway.yaml`):**

```yaml
models:
  fast:
    endpoint: http://localhost:4000
    model: fast
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: fast
```

**Example (illustrative, a `tools` entry for the `legacy-triage` agent
above):**

```yaml
tools:
  ticket-search:
    kind: mcp
    url: https://tickets.internal/mcp
    credential_source: static_env
    token_env: TICKETS_MCP_TOKEN
```

**Example (illustrative, a `client_credentials` tool resource): an
OAuth-protected MCP resource, where the credential the proxy injects is not
read verbatim from an environment variable but a separate token the broker
mints itself from a generic OAuth identity provider:**

```yaml
tools:
  billing-mcp:
    kind: mcp
    url: https://billing.internal/mcp
    credential_source: static_env
    grant_type: client_credentials
    client_auth: client_secret_basic
    issuer: https://idp.example.com/
    token_endpoint: https://idp.example.com/oauth2/token
    client_id_env: BILLING_MCP_CLIENT_ID
    client_secret_env: BILLING_MCP_CLIENT_SECRET
    scope: billing.read
```

`client_id_env` and `client_secret_env` name the environment variables
holding the client's id and secret; the broker reads them and calls
`token_endpoint` (HTTP Basic per RFC 6749 §2.3.1) at the moment a call to
this resource is actually due, never at `apply` time, and caches the minted
token until shortly before it expires rather than minting one per call.

**Okta note:** an Okta authorization server's `token_endpoint` has the shape
`https://<your-okta-domain>/oauth2/<authorization-server-id>/v1/token` (the
org's default authorization server uses the literal segment `default` in
place of an id). Okta custom scopes are declared on that authorization
server and requested the same way, as a space-delimited `scope` string.

## Control-plane CLI

`agenthof apply` and `agenthof registry enable|disable` — the kill switch —
record every attempt to a hash-chained control log, and `agenthof audit`
gains three verbs to read and, if needed, recover it. See
[`docs/concepts.md`](../concepts.md#control-plane-audit) for what gets
recorded and why; this section is the flag-by-flag and exit-code reference.

| Command | Flags |
|---|---|
| `agenthof apply --config <dir> [--control-log <path>] [--as <user>] [--groups <a,b>] [--token <jwt>]` | `--control-log`, `--as`, `--groups`, `--token` |
| `agenthof registry enable\|disable <agent> --config <dir> [--control-log <path>] [--as <user>] [--groups <a,b>] [--token <jwt>]` | same |
| `agenthof audit control [--control-log <path>]` | `--control-log` |
| `agenthof audit verify control [--control-log <path>] [--expect-head <hex>]` | `--control-log`, `--expect-head` |
| `agenthof audit repair control [--control-log <path>] [--as <user>] [--groups <a,b>] [--token <jwt>]` | `--control-log`, `--as`, `--groups`, `--token` |
| `agenthof investigate [--since <dur\|ts>] [--until <dur\|ts>] [--invoker <id>] [--agent <name>] [--outcome <value>] [--run <run-id>] [--config-hash <sha256:…>] [--json] [--log-dir <dir>] [--control-log <path>]` | `--since`, `--until`, `--invoker`, `--agent`, `--outcome`, `--run`, `--config-hash`, `--json`, `--log-dir`, `--control-log` |

### `--control-log`

Path to the control-plane ledger. Default `.agenthof/control.jsonl`,
resolved relative to the current working directory — run these commands
from the repository root, or pass
`--control-log` explicitly. Keep it out from under any directory passed to
`--log-dir`: `runs prune` skips a control log and a `*.torn-*` fragment only
by name (`control.jsonl` and anything containing `.torn-`) — a control log
saved under a different name inside `--log-dir` has no such protection and
can be pruned like any other aged `.jsonl` file.

### `--as`, `--groups`, `--token`

The same invoker-identity flags `agenthof run` takes. `--as` asserts an
invoker identity (default: the OS user); `--groups` is a comma-separated
list recorded alongside it — self-asserted, not verified, and not checked
against any role's `allowed_groups` by these commands, so it authorizes
nothing here on its own. `--token` authenticates the invoker from a raw
OIDC ID token instead (env `AGENTHOF_TOKEN` fallback); when given, identity
comes from the verified token rather than `--as`/`--groups`, and
`AGENTHOF_OIDC_ISSUER` must be set in the environment or the command exits
2 (a usage error, no control event recorded) before doing anything else. A
`--token` that fails verification does not fail silently: it is recorded
as a `refused` control event (reason `token_verification_failed`) and the
command exits nonzero.

### `--expect-head`

`agenthof audit verify control` only. The control-ledger head hash (hex) to
check the freshly verified chain against — a hash Agenthof printed to
stdout after some earlier append, saved somewhere off this machine (see
[`docs/concepts.md`](../concepts.md#control-plane-audit)). Only the hash is
compared; the accompanying event count is informational.

### `--since`, `--until`

`agenthof investigate` only. Each takes either a bare duration — a Go
duration string, or one suffixed `d` for days (`1h`, `720h`, `180d`), the
same grammar `runs prune --older-than` uses — meaning "this long ago,
relative to now", or an absolute RFC3339 timestamp; either form is
normalized to UTC. A value that parses as neither exits 2. `--since` is
**inclusive** (an event at exactly that time is included); `--until` is
**exclusive** (an event at exactly that time is not). Omit either to leave
that end of the window open.

### `--invoker`, `--agent`, `--outcome`, `--run`, `--config-hash`

`agenthof investigate` only. Each is an **exact-match** filter — no
normalization, no substring matching:

- `--invoker <subject>` matches the invoker's subject exactly as recorded.
- `--agent <name>` matches the agent name exactly.
- `--run <run-id>` narrows the timeline to a single run's log.
- `--config-hash <sha256:…>` matches the full `config_hash` string exactly.
- `--outcome <value>` matches an event's outcome exactly — and **the literal
  you need depends on which kind of event you're after**, because run
  events and control events were never recorded with the same outcome
  vocabulary: a **run** event's outcome is one of
  `succeeded | failed | refused`; a **control** event's (`apply`,
  `enable`/`disable`, `repair`) outcome is one of
  `success | refused | rejected | error`. `--outcome succeeded` selects only
  successfully finished runs, `--outcome failed` selects only failed runs,
  and `--outcome refused` selects refused **runs and refused control
  events together** — `refused` is the one literal both vocabularies share.
  `--outcome success` selects successful control actions only — note
  "succeeded" (run) vs "success" (control). Run `investigate` twice (once
  per vocabulary) to see both kinds of outcome.

### `--json`

`agenthof investigate` only. Renders the `investigate/1` JSON contract
(below) on stdout instead of the plain-text timeline. It changes only the
rendering — never the exit code.

### `--log-dir`

`agenthof investigate` only, in this section (`agenthof run` also takes it,
documented alongside the engine). Default `.agenthof/runs`. `investigate`
reads every `<log-dir>/r-*.jsonl` run log it finds there, in addition to
`--control-log`. Not to be confused with `--log-level` / `--log-format`, which
configure the operational log on stderr — see [`logging.md`](logging.md).

### Exit codes

`agenthof apply` / `agenthof registry enable|disable`:

| Exit | Meaning |
|---|---|
| `0` | Success — config validated, or the agent's enabled bit flipped; a `success` event was recorded |
| `1` | The attempt was rejected, refused, or errored (a `rejected`/`refused`/`error` event was recorded); or the control ledger itself is torn or broken, in which case nothing is recorded and the command names the `agenthof audit repair control` invocation to run; or (`registry enable\|disable` only) the flip itself landed but the config hash or the append that would record it then failed — printed as `state changed; event NOT recorded`, the one case where the registry changed with no event to show for it |
| `2` | Usage error — bad flags, or `--token` given without `AGENTHOF_OIDC_ISSUER` set |

`agenthof audit control`:

| Exit | Meaning |
|---|---|
| `0` | Rendered the chain — including a chain that verifies clean but is tainted (a `repair` event was ever appended): the taint shows in the trailing integrity line, but only `audit verify control` turns it into a distinct exit code |
| `1` | No control log at that path yet, another open/IO failure, or a torn/broken chain — a torn or broken chain still renders whatever valid prefix was recovered, with the failure named in the trailing integrity line |
| `2` | Usage error |

`agenthof audit verify control`, checked in this order:

| Exit | Meaning |
|---|---|
| `1` | No control log at that path yet, another open/IO failure, or a torn/broken chain |
| `3` | The chain is tainted — a `repair` event has ever been appended to it (checked, and reported, before `--expect-head` is) |
| `4` | `--expect-head` was given and does not match the verified head |
| `0` | None of the above — the chain is clean and, if given, `--expect-head` matched |
| `2` | Usage error |

`agenthof audit repair control`:

| Exit | Meaning |
|---|---|
| `0` | A torn tail was repaired: the damaged bytes were moved to a `<log>.torn-<timestamp>` fragment, the live log truncated to its last valid record, and a `repair` event appended — the ledger is now tainted |
| `1` | No control log at that path; the ledger is not torn (already clean, or broken at a well-formed record mid-file — only a torn tail is repairable this way); `--token` failed verification; or another IO error. None of these write a control event, since the ledger being repaired may itself be the file in question |
| `2` | Usage error |

`agenthof investigate`:

| Exit | Meaning |
|---|---|
| `0` | Every source (each run log under `--log-dir`, plus `--control-log`) verified clean, or nothing was recorded at all (no logs found) |
| `1` | Any source is torn or broken, or an open/IO error was hit reading a source that does exist |
| `3` | Tainted only — the control log carries a `repair` record and every source is otherwise clean (no source torn or broken) |
| `2` | Usage error — a bad flag, or a `--since`/`--until` value that isn't a duration or an RFC3339 timestamp |

`--json` never changes this exit code — it only changes the rendering — and
the JSON envelope's `integrity.ok` always equals `(exit == 0)`.

### The `investigate/1` JSON contract

`--json` renders this envelope instead of the text timeline:

```jsonc
{
  "v": "investigate/1",
  "query": {
    // only the filters that were actually set, e.g.:
    "since": "2026-09-20T00:00:00Z",
    "outcome": "refused"
  },
  "sources": [
    { "path": ".agenthof/runs/r-a1b2c3.jsonl", "kind": "run", "integrity": "verified", "count": 6 },
    { "path": ".agenthof/control.jsonl", "kind": "control", "integrity": "verified", "count": 3 }
  ],
  "events": [
    {
      "time": "2026-09-20T18:04:11Z",
      "source": "run",
      "run_id": "r-a1b2c3",
      "kind": "run_refused",
      "invoker": { "subject": "dana@example.com", "issuer": "asserted", "method": "asserted" },
      "role": "software-engineer",
      "workflow": "fix-bug",
      "outcome": "refused",
      "reason": "configuration invalid: ..."
    }
  ],
  "integrity": { "ok": true, "issues": [] }
}
```

Field notes:

- `v` is the contract's version string, `"investigate/1"`. The contract is
  **additive**: future fields may appear, existing ones will not change
  meaning or be repurposed.
- `query` echoes back only the filters you actually passed (`since`, `until`,
  `invoker`, `agent`, `outcome`, `run`, `config_hash`); an unset filter is
  omitted, not rendered as an empty string.
- `sources[]` lists every source `investigate` read: `path`, `kind`
  (`"run"` or `"control"`), `integrity` (`"verified"`, `"torn"`, `"broken"`,
  `"tainted"`, or `"error"` for an open/IO failure), and `count` — the
  number of valid-prefix records parsed from it, before any filter is
  applied.
- `events[]` is the merged, filtered timeline, time-ordered (ties broken by
  source, then run id, then in-source position — the line index within a run
  log, or `seq` within the control log — so 8 steps recorded in the same
  second still come out in a stable order). Each event carries whichever of
  `run_id`, `role`, `workflow`, `agent`, `outcome`, `reason`, `config_hash`,
  `artifact_sha`, or `seq` applies to it (all `omitempty`); `invoker` is
  always present, with `subject`, `issuer`, `method`, and — for a control
  event recorded with `--as` — `asserted_as`. All timestamps are RFC3339
  UTC. There is **no `witness` field** — it is deliberately left out of this
  contract.
- `integrity.ok` mirrors the exit code exactly: `true` iff the exit code is
  `0`. `integrity.issues[]` is **operator-facing prose** (e.g. `"control
  ledger TORN at .agenthof/control.jsonl"`) meant for a human reading the
  output — a program should key off `integrity.ok` and whether `issues` is
  empty, not parse the issue strings themselves; their wording is not part
  of the stable contract the way the field names are.

### Config-join on `audit <run-id>`

`agenthof audit <run-id>` prints a config-join line right after the run's own
timeline, for a run whose `workflow_started` event carries a `config_hash`:
it names the control-plane `apply` that put that exact config in place,
drawn from `--control-log` (default `.agenthof/control.jsonl`). Four forms,
verbatim:

- A matching, successful `apply` at or before the run started:
  `config sha256:<hash> — applied by <subject> (<method>) at <RFC3339 time>`
- The hash instead matches a later `enable`/`disable` rather than any
  `apply`: `config sha256:<hash> — no successful apply on record (matches a
  later enable/disable, not an apply)`
- No control event at all matches the hash:
  `config sha256:<hash> — no successful apply on record`
- The control log is missing, torn, broken, or otherwise unreadable:
  `config sha256:<hash> — control ledger unavailable`

A run recorded before `config_hash` existed omits the join line entirely.

**Guarantee:** `audit <run-id>`'s own exit code (`0` clean, `1`
torn/broken/IO error) is computed from the run's own log alone. The control
log's health — missing, torn, broken, or fine — never changes `audit
<run-id>`'s exit code; at worst it changes the join line's wording to
"control ledger unavailable".
