# Configuration reference

This is the field-by-field reference for the YAML config Agenthof loads and
validates. Every field name and semantic statement below is drawn from two
files, and only those two: the struct comments in
[`internal/config/types.go`](../../internal/config/types.go) (what a field
means and its default) and the rules in
[`internal/registry/validate.go`](../../internal/registry/validate.go) (what
`agenthof apply` accepts or rejects). Behavior that lives elsewhere — how the
engine executes a workflow, how identity and the ledger work, why the
execution tiers exist — is covered in [`docs/concepts.md`](../concepts.md),
not repeated here.

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
| Model | `model` | string | conditionally | falls back to `gateway.yaml`'s `defaults.model` |
| Instruction | `instruction` | string | no | — |
| Tools | `tools` | list of strings | no | none |
| Output | `output` | string | no | — |
| Execution | `execution` | string | no | `contained` |
| Endpoint | `endpoint` | string | conditionally (fronted only) | — |

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

Optional string naming a key under `gateway.yaml`'s `models` map. This check
is skipped entirely for `fronted` agents (see `execution` below). For every
other agent, `apply` resolves the effective model as: `model` if set,
otherwise `gateway.yaml`'s `defaults.model`; if that resolved name is not a
key in `gateway.yaml`'s `models` map, `apply` rejects it with
`unroutable-model`.

### `instruction`

Optional free text. Not checked by `apply`.

### `tools`

Optional list of tool names. Not checked by `apply` for a `contained` agent.
For a `fronted` agent, any non-empty `tools` list is rejected with
`bad-execution` ("fronted agents cannot declare tools; tools are
contained-runtime capabilities").

### `output`

Optional string. Not checked by `apply`.

### `execution`

Optional string; per the comment on `AgentDef.Execution`, the accepted
values are `""`, `"contained"`, or `"fronted"`, and `""` means `contained`
(see `AgentDef.EffectiveExecution`). Any other value is rejected by `apply`
with `bad-execution` ("execution ... must be \"contained\" or \"fronted\"").

### `endpoint`

Per the comment on `AgentDef.Endpoint`, this is fronted-only: "the agent's
HTTP endpoint". `apply` enforces both directions:

- effective execution `fronted` and `endpoint` empty → rejected,
  `fronted-needs-endpoint` ("fronted agents must have an endpoint").
- effective execution `contained` and `endpoint` non-empty → rejected,
  `contained-has-endpoint` ("endpoint is only valid on fronted agents").

**Example (from `examples/config/agents/planner.yaml`, a `contained` agent —
`execution` and `endpoint` omitted, so they default):**

```yaml
name: planner
description: Turns a task into a short numbered plan
model: fast
instruction: |
  You are a planning agent. Produce a short numbered plan for the task.
output: plan
```

**Example (illustrative, `fronted`):**

```yaml
name: legacy-triage
description: Fronts an existing HTTP agent behind the registry
execution: fronted
endpoint: https://legacy.internal/agents/triage
# model and tools are not set: model routing is skipped for fronted agents,
# and a non-empty `tools` list here would fail apply with bad-execution.
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
| AllowedGroups | `allowed_groups` | list of strings | no | none |
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

Optional list of strings. `apply` does not check its contents (see
[`docs/concepts.md`](../concepts.md) for how identity and groups are used
outside of `apply`).

### `budget_usd_month`

Optional float. `apply` does not check its value.

**Example (from `examples/config/roles/accountant.yaml`):**

```yaml
name: accountant
description: Financial operations and reconciliation
workflows: [reconcile-lite]
allowed_groups: [finance]
budget_usd_month: 20
```

## Gateway (`config/gateway.yaml` → `GatewayConfig` / `ModelRoute`)

`GatewayConfig` fields:

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Models | `models` | map of string → `ModelRoute` | conditionally | — |
| Defaults.Model | `defaults.model` | string | no | — |

`ModelRoute` fields:

| Field | YAML key | Type | Required | Default |
|---|---|---|---|---|
| Endpoint | `endpoint` | string | no (not checked by `apply`) | — |
| Model | `model` | string | no (not checked by `apply`) | — |
| APIKeyEnv | `api_key_env` | string | no (not checked by `apply`) | — |

### `models`

A map from a logical model name to a `ModelRoute`. `apply` uses the map's
keys as the set of routable model names when resolving each non-`fronted`
agent's effective `model` (see `model` under Agents, above) — a name not
present as a key here fails with `unroutable-model`. The contents of each
`ModelRoute` entry (`endpoint`, `model`, `api_key_env`) are not themselves
validated by `apply`.

### `defaults` / `defaults.model`

`defaults` is a nested object holding one field, `model` (optional string).
`GatewayConfig.Defaults.Model` is used as the fallback effective `model` for
any non-`fronted` agent that leaves its own `model` empty (see `model` under
Agents, above).

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
