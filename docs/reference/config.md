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
| Tools | `tools` | list of tool grants ({resource, tools} or {resource, mode} objects) | no | none |
| Output | `output` | string | no | — |
| Execution | `execution` | string | no | `fronted` |
| Endpoint | `endpoint` | string | yes | — |
| Exec | `exec` | object | no | none |
| MaySpawn | `may_spawn` | list of `{role, workflow}` objects | no | none (the agent spawns nothing) |

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

Optional list of tool grants. Each entry is an object naming a tool resource
declared under `gateway.yaml`'s `tools` map (see [`tools`](#tools-1) under
Gateway, below) with these keys:

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Resource | `resource` | string | yes | — |
| Tools | `tools` | list of strings | yes when `mode` is absent; non-empty when present | — |
| Mode | `mode` | string | no | `""` |

A grant takes one of four forms:

- `{resource, mode: all}` — every tool the resource exposes;
- `{resource, mode: read-only}` — the tools listed in that resource's
  [`read_only_tools`](#tools-1) on the gateway catalog entry;
- `{resource, tools: [...]}` — exactly the named tools;
- `{resource, tools: [...], mode: read-only}` — exactly the named tools, and
  `apply` rejects any of them that is not in the resource's
  `read_only_tools`.

These shapes are rejected with `bad-tool-grant`: a bare resource id on its
own (`- ticket-search`), which is no longer a grant — the error names both
replacements, a `tools` list or `mode: all`; an object with neither `tools`
nor `mode`; a `tools` list that is empty (or `null`); `mode: all` together
with `tools`; and any `mode` other than `all` or `read-only`. The file
loader also rejects an object with any key other than `resource`, `tools`,
and `mode`, or with an empty `resource`, so a misspelled key can never
widen a grant. A `mode: read-only` grant on a resource that declares no
`read_only_tools` is also `bad-tool-grant`. Every-tool access is therefore
always a deliberate, visible `mode: all`, never something a resource id
grants by omission.

`apply` rejects an entry whose resource is not declared in `gateway.yaml`
with `unknown-tool` ("agent references tool ..., which is not a declared
gateway tool resource") and an empty tool name with `bad-tool-grant`. A
resource granted more than once is `bad-tool-grant` ("resource ... is
granted more than once and at least one of those grants is not an all-tools
grant; merge them into one grant") unless every grant of it is
`mode: all`. `apply` does not check tool names against the resource itself;
a name a grant lists that the resource does not expose fails the step at
run time instead. The agent reaches its
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
A tool resource's `url` accepts the same `unix://` form (a bridge socket,
see [`tools`](#tools-1) below). `token_endpoint` stays on the stricter
https-or-loopback rule, because that call carries a client secret to a
remote host.

`endpoint` stays required for every agent, but under spawn it is not
consulted: a spawned child's agents are dialed at the compartments the
supervisor provisioned for that child, whatever this field names. See
[`spawn_supervisor`](#spawn_supervisor).

Every fronted step receives `X-Agenthof-Proxy-URL` and
`X-Agenthof-Run-Token`, whether or not the agent declares `tools` or `exec`.
The model door is `POST <proxy URL>v1/chat/completions` with that run token.
An agent uses the doors it needs and ignores the rest. See
[`lifecycle-model.md`](../lifecycle-model.md).

### `exec`

Optional, and only on a `fronted` agent. Declares the commands the agent may
have run on its behalf. The exec door is first-hand: Agenthof authorizes
every command against `allow`, asks the declared operator-side runtime
(`refexec`) to run it over a `unix://` socket, and records that runtime's
first-hand account (`runtime_attestation`). Agenthof never runs the command
itself, and the agent never runs it either. The door requires an
operator-run runtime — a Linux host with rootless podman — and there is no
exec without one.

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Runtime | `runtime` | string | yes; `refexec` is the only value implemented | — |
| URL | `url` | string | yes; `unix://<absolute path>` of the runtime's socket | — |
| Timeout | `timeout` | duration string | yes; at least `1s`, such as `5m` | — |
| Allow | `allow` | list of objects | yes, non-empty | — |

`runtime` names the trusted operator-side runtime that runs the command —
only `refexec` is implemented — `url` is that runtime's Unix socket as
`unix://<absolute path>` (a trusted runtime is reached only over a local
socket, as `runtime: refbridge` on a tool resource; never a path under
`refbox_socket_dir`, which is mounted into agent compartments), and
`timeout` is the per-command deadline Agenthof enforces on its call to the
runtime: a duration string of at least `1s`, such as `5m`. Keep it below
the step timeout, which otherwise fails the step first. Under spawn `url`
is not consulted: a spawned child's exec door reaches the child's own
runtime, bound to the child's workspace.

The key `mode` is retired. An `exec` block that still carries it — `mode:
attested` or `mode: runtime` — is rejected at `apply` with
`bad-exec-config: line N: exec.mode is no longer supported; exec is always
first-hand via a runtime (set runtime/url/timeout)`. The key is never
silently dropped: exec is first-hand only, and a config that says otherwise
is refused, not reinterpreted. Ledgers written before this change may hold
`exec` events with `mode: attested`; they still verify and render — see
[`lifecycle-exec.md`](../lifecycle-exec.md#the-retired-agent-asserted-routes).

Each `allow` entry:

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Exe | `exe` | string | yes | — |
| ArgsPrefix | `args_prefix` | list of strings | no | empty (any arguments) |

An argv matches an entry when `argv[0]` equals `exe` exactly (no glob) and
`args_prefix` is a prefix of the arguments that follow. The rest of the argv
is unconstrained. An empty `args_prefix` matches any invocation of that
`exe`. An argv shorter than the prefix does not match.

`apply` rejects, all with `bad-exec-config`:

- `exec` on an agent whose effective execution is not `fronted`;
- a `mode` key (retired; see above);
- `runtime` absent, or anything other than `refexec`;
- a `url` that is not an absolute `unix://` path, or one inside
  `refbox_socket_dir`;
- a `timeout` absent or below `1s`;
- an empty `allow`;
- an `allow` entry whose `exe` is empty.

Allowlisting an executable trusts that program's whole capability surface.
`exe: go` with `args_prefix: [test]` still permits `go test` with whatever
flags that program accepts. An entry whose `exe` is a shell or interpreter
and whose prefix is an eval flag (`sh -c`, `python -c`, and the like) makes
the allowlist match arbitrary commands while the ledger still records them as
allowlisted. Agenthof does not detect or reject those entries. Writing a
safe allowlist is the operator's obligation; the runtime's compartment is
what bounds the damage a bad entry can do.

**Example:**

```yaml
name: builder
execution: fronted
endpoint: https://builder.internal/run
exec:
  runtime: refexec
  url: unix:///run/agenthof-exec/refexec.sock
  timeout: 5m
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
  - resource: ticket-search
    mode: all                            # every tool ticket-search exposes
  - resource: billing-mcp
    tools: [get_invoice, list_invoices]  # only these two of billing-mcp
# `model` is not checked. Each entry must name a resource under
# gateway.yaml's `tools` map (see `ticket-search` and `billing-mcp` in the
# Gateway examples below), or apply rejects the agent with unknown-tool.
```

**Example (illustrative, a read-only grant):**

```yaml
name: billing-reader
execution: fronted
endpoint: https://billing-reader.internal/run
tools:
  - resource: billing-mcp
    mode: read-only                     # only billing-mcp's read_only_tools
# A second grant of billing-mcp in this list would be bad-tool-grant: a
# resource may repeat only when every grant of it is mode: all.
```

### `may_spawn`

Optional list of `{role, workflow}` objects. Each names one child run the
agent may ask the **spawn door** (`POST <proxy-url>/spawn`) to start: the
`role` the child runs as and the `workflow` it runs. An agent with no
`may_spawn` spawns nothing — the door refuses and records the attempt. Both
values are matched exactly. A child run is a full governed run: it passes the
same registry gate as a root run (the role must own the workflow and admit the
invoker), under the **same invoker** as the parent — a child never gains
authority the invoking human does not have. Each child gets its own run id,
its own hash-chained ledger in the same run-log directory, and a binding that
names its parent (`parent_run_id`) and its depth (`depth`; a root run is 0).
The binding is forwarded to the agent as request headers; it is not signed.

`apply` rejects, with `bad-spawn-target`: an entry missing `role` or
`workflow`; a `role` that does not exist; a `workflow` that does not exist; a
pair the role does not own; the same pair listed twice. Declaring
`may_spawn` anywhere makes the gateway's [`spawn`](#spawn) block required.
See [the life of a spawn](../lifecycle-spawn.md).

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
| RefboxSocketDir | `refbox_socket_dir` | string (absolute path) | no | empty (TCP loopback) |
| SpawnSupervisor | `spawn_supervisor` | string (`unix://<absolute socket path>`) | yes when any agent declares `may_spawn`; otherwise optional (a malformed value is still rejected) | — |
| Spawn | `spawn` | object (`max_depth`, `max_parallel`, `max_total_spawns`, `reject_cycles`) | yes when any agent declares `may_spawn`; otherwise optional (a malformed value is still rejected) | — |
| StepTimeout | `step_timeout` | duration string | no | `5m` |

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
| URL | `url` | string | yes; must be `https`, `http` to a loopback host, or `unix://` plus an absolute socket path | — |
| CredentialSource | `credential_source` | string | yes | — |
| TokenEnv | `token_env` | string | yes for the direct-bearer grant (`grant_type: ""`); must not be set for `token_exchange` | — |
| GrantType | `grant_type` | string | no | `""` (direct-bearer); the other accepted values are `client_credentials` and `token_exchange` |
| ClientAuth | `client_auth` | string | yes for `client_credentials` and `token_exchange` (must be `client_secret_basic`) | — |
| Issuer | `issuer` | string | yes for `client_credentials`; must not be set for `token_exchange` | — |
| TokenEndpoint | `token_endpoint` | string | yes for `client_credentials` and `token_exchange`; must be `https`, or `http` to a loopback host | — |
| ClientIDEnv | `client_id_env` | string | yes for `client_credentials` and `token_exchange` | — |
| ClientSecretEnv | `client_secret_env` | string | yes for `client_credentials` and `token_exchange` | — |
| Scope | `scope` | string | no (not checked by `apply`) | — |
| Audience | `audience` | string | yes for `token_exchange`; must not be set on other grants | — |
| ReadOnlyTools | `read_only_tools` | list of strings | no | empty (no read-only grant) |
| Runtime | `runtime` | string | no | `""` (no trusted runtime) |

`read_only_tools` is the operator's list of the tools on this resource that
a `mode: read-only` agent grant may use. A tool whose name is not in the
list is treated as mutating. Entries must be non-empty and unique, or
`apply` rejects the resource with `bad-tool-resource` ("read_only_tools
entries must be non-empty and unique"). `apply` cannot check the names
against the upstream, since it makes no network call. At run time a listed
name the upstream does not expose is skipped with a warning, and a
`mode: read-only` grant that matches no exposed tool fails the step.

`runtime` declares that a trusted operator runtime fronts this resource and
attests first-hand, on every result, what it ran. The only accepted value is
`refbridge`, and it requires a `unix://` url — `apply` rejects
`runtime: refbridge` on an `https` or loopback `http` url with
`bad-tool-resource` ("runtime refbridge requires a unix:// url"), and any
other value with `bad-tool-resource` ("runtime ... is not implemented (only
refbridge)"). When set, every `tool_call` event that carries a result from
this resource carries the runtime's attestation (`runtime_attestation`: the
spawned command, the answering child's pid and generation, and environment
variable NAMES — never a value); a result that arrives without a well-formed
attestation fails the call with reason `runtime attestation missing` or
`runtime attestation malformed`. Leave it unset for an ordinary MCP server:
any such claim on its results is stripped and never recorded.

`apply` requires `kind` to be exactly `"mcp"` and `url` to be set and
`https` (or `http` only to a loopback host — `localhost`, `127.0.0.1`, or
`::1`, or `unix://` plus an absolute socket path). The gateway injects a
credential on every call to that url, so a plaintext url on a remote host is
rejected at apply time, as for `token_endpoint` (which, unlike `url`, does
not admit `unix://`). A `unix://` url names a socket on Agenthof's own host
— a stdio MCP server fronted by the reference bridge, `deploy/refbridge` —
that never touches the network and is reachable only through that socket's
directory permissions; the path after `unix://` is the socket only (the MCP
route is the socket's root), and a relative path is rejected. A resource
that fails either check is rejected with `bad-tool-resource` ("tool resource
... must set kind: mcp", or "url must be set and https (or loopback http, or
a unix:// socket)"). `apply` separately requires
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
time); `"token_exchange"` — a resource called *on behalf of the invoker*
(see [`lifecycle-tool.md`](../lifecycle-tool.md#on-behalf-of-the-invoker)) —
requires the same client coordinates plus
`audience` (the RFC 8693 audience the exchanged upstream token is for —
distinct from `AGENTHOF_OIDC_AUDIENCE`, which governs tokens presented to
Agenthof), and rejects `token_env` (an on-behalf-of resource has no direct
bearer) and `issuer` (the exchange is keyed by the invoker's token, not by
an issuer); any other `grant_type` is
rejected as not implemented. Setting `audience` on the direct-bearer or
`client_credentials` grant is rejected. `scope` is optional and not
validated or required by `apply`; when set on a `client_credentials` or
`token_exchange` resource, the broker forwards it verbatim, as a single
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
`tools` list (see [`tools`](#tools) under Agents) names ids from this map
inside a `{resource, ...}` object; `apply` rejects an agent entry
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
`/exec/run`, `/v1/chat/completions`, `/spawn`; the retired `/exec/authorize` and
`/exec/attest` answer only a recorded refusal). The run token
still travels in the `Authorization` header. The value must be an absolute
path (`bad-refbox-socket-dir` otherwise): it is mounted into agent
compartments at the same path inside and out, and it is what every socket's
placement is checked against. `apply` does not check that the
directory exists. Keep the directory's path short: a Unix socket path has a
small operating-system length limit, and a path that exceeds it fails the
step at listen time.

`deploy/refbox/` is a reference recipe. Its socket directory defaults to
`$XDG_RUNTIME_DIR/agenthof` (user-owned, so a rootless `mkdir` works; `/run`
itself is root-owned). Set `refbox_socket_dir` to that same directory, and
set the agent `endpoint` to `unix://` plus that directory, a `/`, and the
agent's socket file name — `unix:///run/agenthof/refbox-echo.sock` for the
default (`refbox-echo.sock`; the recipe's `REFBOX_SOCKET` variable names
another, such as `refbox-langchain.sock` for the Python agent). The adapter
dials the endpoint; the recipe's `-socket` flag only chooses where the
compartment listens. The checked-in demo config
uses `/run/agenthof` as a placeholder, because YAML cannot expand
`$XDG_RUNTIME_DIR`. The two paths must match. See
[the life of a run](../lifecycle.md#a-reference-compartment-refbox).

### `spawn_supervisor`

The compartment supervisor every spawned child is provisioned through, as
`unix://` plus the absolute path of its socket. **Required as soon as any
agent declares [`may_spawn`](#may_spawn)**: a child run is a full governed
run in compartments of its own, and with no supervisor there is nowhere to
start one, so `apply` rejects the config with `spawn-supervisor-required`
rather than letting a child run beside its parent. With no `may_spawn`
anywhere the field is not needed.

The value must be a `unix://` socket with an absolute path
(`bad-spawn-supervisor` otherwise), and its directory must not be inside
[`refbox_socket_dir`](#refbox_socket_dir), which is mounted into agent
compartments — an agent could otherwise reach the supervisor directly
(`bad-spawn-supervisor`). `apply` does not check that the socket exists.
When the spawn door dials it, the socket's directory must be mode `0700`
and owned by the user Agenthof runs as, the same gate every operator-side
runtime insists on; otherwise the spawn is refused and recorded as
`spawn compartment unavailable`.

The reference supervisor is `deploy/refspawn/`; see
[the life of a spawn](../lifecycle-spawn.md).

### `spawn`

The bounds of the delegation tree the spawn door may build. **Required as
soon as any agent declares [`may_spawn`](#may_spawn)** — including when there
is no `gateway.yaml` at all: config is law, and a missing cap is rejected at
`apply` with `spawn-policy-required`, never read as unbounded. With no
`may_spawn` anywhere the block is not needed.

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| MaxDepth | `max_depth` | integer ≥ 1 | yes when spawn is in use | — |
| MaxParallel | `max_parallel` | integer ≥ 1 | yes when spawn is in use | — |
| MaxTotalSpawns | `max_total_spawns` | integer ≥ 1 | yes when spawn is in use | — |
| RejectCycles | `reject_cycles` | bool | no | `false` |

- `max_depth` — how deep the tree may go. A root run is depth 0 and its
  children are 1; a spawn whose child would sit deeper than `max_depth` is
  refused. `max_depth: 1` lets a root run spawn and its children not.
- `max_parallel` — how many children one run may have in flight at once.
  Checked and reserved atomically, so N simultaneous requests cannot each
  see room for one more.
- `max_total_spawns` — how many children one run may start over its whole
  life, across all of its steps. A refused attempt starts nothing and does
  not count; a child that started counts whatever its outcome (it has a
  ledger of its own). The whole tree under one root is bounded by the sum
  over k = 1..`max_depth` of `max_total_spawns`^k.
- `reject_cycles` — when `true`, `apply` rejects (`spawn-cycle`) any cycle in
  the agent-type spawn graph: an edge A → B exists when A's `may_spawn` names
  a workflow with a step run by B; a self-loop counts. When `false` (the
  default) such reuse of a type deeper in the tree is allowed and `max_depth`
  bounds it. Because `may_spawn` fully determines what can be reached, this
  static check is complete; there is no runtime check.

A negative cap is rejected with `bad-spawn-policy` whether or not spawn is in
use. Every refusal at the door is recorded on the parent's ledger as a
`spawn` event with a fixed reason.

### `step_timeout`

Optional duration string, default `5m`; at least `1s` or `apply` rejects it
with `bad-step-timeout`. The deadline every step runs under — it is at once
the engine's per-step deadline and the timeout on the request Agenthof makes
to the agent's endpoint, one knob. A spawned child runs under the step that
asked for it, so a whole subtree shares the invoking step's deadline: size
`step_timeout` for the subtree, not for one step.

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
    read_only_tools: [get_invoice, list_invoices]
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

**Example (illustrative, a `token_exchange` tool resource): a per-user
service — every human has their own account there — that the agent must
reach as the invoking human, not as a service identity. Agenthof exchanges
the invoker's verified token for one audienced to this upstream (RFC 8693)
and injects that:**

```yaml
tools:
  crm-mcp:
    kind: mcp
    url: https://crm.internal/mcp
    credential_source: static_env
    grant_type: token_exchange
    client_auth: client_secret_basic
    token_endpoint: https://idp.example.com/oauth2/token
    audience: https://crm.internal
    client_id_env: CRM_MCP_CLIENT_ID
    client_secret_env: CRM_MCP_CLIENT_SECRET
    scope: crm.read
```

The run must be invoked with `--token` (a token the configured
`AGENTHOF_OIDC_ISSUER` verifies): a run that would reach this resource with
a dev `--as` identity is refused before it starts, and the refusal is
recorded (`run_refused`, reason `obo requires a verified invoker token`).
The exchanged token is cached per resource and per invoker, and
re-exchanged, from the *same* inbound token, shortly before the exchanged
token expires — so a cached token stays in use until its own refresh point
even if the inbound token has expired by then, and it is the next exchange
that fails, recording the call `failed`. There is no refresh token and no re-authentication. The upstream,
not Agenthof, is what checks that the exchanged token's audience is itself.
See [`lifecycle-tool.md`](../lifecycle-tool.md#on-behalf-of-the-invoker) for
the life of an on-behalf-of call.

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
2 (a usage error, no control event recorded) before doing anything else.
`AGENTHOF_OIDC_CLIENT_ID` (default `agenthof`) is the audience a token must
name; `AGENTHOF_OIDC_AUDIENCE`, when set, is a second accepted audience —
the resource-server audience of an access token minted for Agenthof's API
rather than for the login client — and changes nothing when unset. Both
apply wherever `--token` does, `agenthof run` included. For `agenthof run`
only, `AGENTHOF_OIDC_SUBJECT_TOKEN_TYPE` names the kind of inbound token
this deployment presents when exchanging it on the invoker's behalf (RFC
8693 `subject_token_type`; default
`urn:ietf:params:oauth:token-type:access_token`; an ID-token deployment sets
`urn:ietf:params:oauth:token-type:id_token`). The verified token itself is
held only for the run and is never recorded. A
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
- `--run <run-id>` narrows the timeline to that run **and every run spawned
  under it** (a delegation tree: each child ledger names its parent, so the
  tree is walked down from the id you give; a child whose parent's log was
  pruned still appears under the parent's id). Control events are left out.
  In the text timeline, a spawned child's lines are indented two spaces per
  level of depth and carry a `parent=<run-id>` tag.
- `--config-hash <sha256:…>` matches the full `config_hash` string exactly.
- `--outcome <value>` matches an event's outcome exactly — and **the literal
  you need depends on which kind of event you're after**, because run
  events and control events were never recorded with the same outcome
  vocabulary: a **run** event's outcome is one of
  `succeeded | failed | refused | cancelled` (`cancelled` is a run whose
  context ended between steps — a spawned child torn down with its parent,
  for instance); a **control** event's (`apply`,
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
  `artifact_sha`, `seq`, `parent_run_id`, or `depth` applies to it (all
  `omitempty`; `parent_run_id` and `depth` place a spawned child run in its
  delegation tree, and a root run has neither); `invoker` is
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
