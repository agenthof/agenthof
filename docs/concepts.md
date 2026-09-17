# Concepts

This page summarizes the ideas behind Agenthof's design. Most of it draws
only from two documents — [`docs/design/v1-design.md`](design/v1-design.md)
(the working design spec) and [`docs/constitution.md`](constitution.md) (the
binding invariants; where the two disagree, the constitution wins) — and
does not introduce anything beyond what they state. The "Execution tiers"
section below is the one exception: it also describes normative,
code-enforced behavior (what the `execution` field actually does and what
gets recorded), since that mechanism is load-bearing enough to document
precisely rather than only in the terms the design spec used before it was
built. For the field-level mechanics of config, see
[`docs/reference/config.md`](reference/config.md).

## The shape: roles, workflows, agents

The design spec fixes a one-way reference direction: **Roles → Workflows →
Agents → Tools** (v1-design.md §3). A role owns one or more workflows; a
workflow is composed of agents that hand off to each other on success and
bounce back on failure; an agent is unconstrained in kind — a RAG agent, a
coder, a classifier are all the same schema (v1-design.md §3, "Agent kind is
deliberately unconstrained"). The **registry** is not a folder on disk but a
behavior: the loaded, validated union of the `agents/`, `workflows/`, and
`roles/` config directories plus `gateway.yaml` — reference resolution,
enabled/disabled state, and privileges all live there (v1-design.md §3).
`apply` validates everything at once and reports every problem with a
file:line error; disabling an agent that a workflow still depends on is
itself a validation failure naming every dependent workflow (v1-design.md
§3) — this is deliberate: "governance you can see."

## Two planes

The provenance note in the design spec names the pattern the runtime
architecture follows: **control/data-plane separation** (v1-design.md §1,
"Provenance note"). In Agenthof's own package layout (v1-design.md §5):

- **Control plane** — `registry/` (load, validate, resolve, enable/disable,
  privileges), `engine/` (event-sourced execution), `identity/`
  (authenticators, delegation binding), and `audit/` (ledger write/read).
  This is the layer that decides what is allowed to run and records what
  did.
- **Data plane** — `gateway/`, explicitly tagged "data planes" in the
  runtime-architecture table (v1-design.md §5): it resolves models and
  provisions LiteLLM (keys, budgets), and carries the schema slot reserved
  for a V2 `tools:` block.

`agentrt/` (materializing ADK-Go agents from registry entries, plus the
jailed tool catalog) and `adapter/` (fronting an existing external agent)
are driven by the control plane and are where an agent's actual work
happens.

## The three governed surfaces

The "Gateways" decision in the spec's strategy table (v1-design.md §2) names
three, "all first-class from day one; designed-in ≠ built-now":

1. **Model gateway** — the data plane for model calls. It is a
   LiteLLM-class facade: run, never rebuild. It holds per-role virtual keys
   with budgets (v1-design.md §4.2).
2. **(V2) tool/MCP gateway** — reserved as a schema slot (`tools:` in
   `gateway.yaml`) but not built in V1; V1 instead ships a jailed tool
   catalog (list/search/read/edit/write; no exec) as part of the agent
   runtime (v1-design.md §2, §6).
3. **Control tower** — "the platform itself (`config/` + `apply` +
   registry)" (v1-design.md §2). Unlike the other two, this isn't a network
   facade; it's the config/validate/registry path described above.

## Execution tiers

Every agent runs under one of two execution tiers, chosen by its registry
entry's `execution` field: `contained` (the default — empty `execution`
means `contained`) or `fronted`.

**`contained`** is the `agentrt/` path: the agent is materialized as an
ADK-Go agent node running inside Agenthof's own runtime, behind the jailed
tool catalog (v1-design.md §5) — this is containment *by construction*: a
jailed workspace (path-confined, symlink-hardened, no dotfile/VCS-metadata
access) and no exec tool, so there is nothing for the agent to escape
through (constitution Article I, v1-design.md §4.3). A contained agent may
not declare an `endpoint`, and its `model` is resolved and checked against
`gateway.yaml` the normal way (see
[`docs/reference/config.md`](reference/config.md#model)).

**`fronted`** is the `adapter/` path: the agent is an external HTTP service
reachable at its registry entry's `endpoint` — in V1, "one adapter — a
generic OpenAI-compatible/HTTP agent endpoint registered as an agent"
(v1-design.md §5, §6, "govern what you already have"). Because the agent's
own code runs outside Agenthof, its internals cannot be contained the way a
contained agent's can; instead it is **governed at the doors it has to pass
through to act as an agent of the platform** — the same identity, ledger,
and (where applicable) model/tool gateway machinery every agent is subject
to. Put differently: a fronted agent's internals are *attested*, not
*enforced* — Agenthof governs what crosses the boundary (the call in, the
result out, the identity and ledger entries around it), not what the
external service does internally. A fronted agent may not declare `tools`
(tools are a contained-runtime capability) and its `model` routing is not
checked, since it isn't calling through Agenthof's model gateway the way a
contained agent does (see
[`docs/reference/config.md`](reference/config.md#execution) for the exact
`apply` rules `fronted`/`contained` and `endpoint` interact under). A fronted
agent's failure is not special-cased: "Adapters: fronted-agent
timeout/error = a normal step failure (same fail-back semantics)"
(v1-design.md §8) — it participates in the workflow's ordinary fail-back
graph like any other step.

The tier is not just a validation-time concept: it is **recorded on the
registry entry** (the agent's `execution` field, as loaded from config) and
**stamped on every step event the engine writes to the ledger** (the same
`execution` value, carried on `step_started`, `step_succeeded`, and
`step_failed`). That means `audit` can show, for each step of a run, which
guarantee applied to it — whether that step ran inside Agenthof's own
containment or was handed off to an externally-fronted, doors-governed
agent — without having to cross-reference the config separately.

See [`docs/reference/config.md`](reference/config.md) for the `execution`
and `endpoint` fields that select and configure this at the agent level, and
for the validation rules `apply` enforces around them.

## Identity: three identities per action

Both the constitution (Article II) and the design spec (§4.1) describe the
same three identities carried by every action:

1. **Invoker** (human) — subject, issuer, and groups, established by a
   pluggable authenticator: `static` for dev (`--as user@x` / OS user;
   ledger records `method: asserted`) or `oidc` for production (validates a
   JWT from any OIDC identity provider; ledger records `method: oidc`).
2. **Agent** (workload) — its entry in the registry. "The registry is the
   agent IdP" — no agent gets an external identity object; it is free,
   instant, and revocable via `enabled: false` (v1-design.md §4.2,
   constitution Article II).
3. **Delegation binding** (per run) — `invoker → role → workflow → agent →
   run-id`, stamped on every ledger event and every gateway call (both
   documents, identically worded).

The design spec calls this "the identity inversion": agents get identity
from the registry rather than from an external IdP, external credentials
live only in gateways (never in an agent), and attribution rides the ledger
rather than the credential — "authenticate as the machine, attribute to the
human, per action" (v1-design.md §4.2). Only mature, universally supported
standards are load-bearing — OIDC login and M2M client-credentials; emerging
agent-identity standards (RFC 8693 token exchange, SPIFFE/WIMSE, IdP
agent-SSO products) are optional V2 federation upgrades, never prerequisites
(v1-design.md §4.2, constitution Article II).

## Containment

Constitution Article I and design spec §4.3 state the same guarantee: agents
get no raw network access, no shell, and no ambient credentials. Capability
reaches an agent only through governed, logged doors — the model gateway
(metered, budgeted), the tool catalog (the tool gateway in V2, allowlisted
and logged), and a jailed workspace (path-confined, symlink-hardened, no
dotfile or VCS-metadata access). Every one of those doors writes to the
ledger. Per the constitution, no change may add an agent-reachable exec
tool, an unmediated network call, or a credential stored where an agent's
config or runtime can read its value.

## The ledger

Every action an agent takes, and every refusal — invalid identity, exceeded
budget, disabled agent — is an event in the ledger, and every event carries
the full delegation binding (constitution Article III). The ledger is
hash-chained: each event carries the SHA-256 of its predecessor's serialized
line, genesis being the empty string, which makes tamper-evidence a provable
property rather than a claim (constitution Article III, v1-design.md §7a).
Artifact bodies never enter the immutable ledger — only a SHA-256 hash and a
preview of at most 200 characters; bodies live in a separate, prunable store
(constitution Article III, v1-design.md §7a). Secrets and full artifact
bodies are never written to an event, under any circumstance.

The design spec's error-handling section (§8) is specific about how
different refusals surface: an invalid or expired JWT is refused *before any
execution* and ledgered as `run_refused{reason}` — refusals are audit events
too. A budget-exceeded gateway call is described more generally, as a
"typed refusal event" visible in `audit`, without naming a single literal
event type the way the identity case does. A step's own failure (including
a fronted agent's timeout or error) is not a refusal at all — it is a normal
step failure that the workflow's fail-back graph handles; only when bounces
are exhausted does the run finish with `workflow_finished{status: failed}`,
and the full chain stays in the ledger rather than the run stopping
silently.

## Config is law

The constitution's Article VI states the schema-evolution rule this whole
config surface follows: roles, workflows, and agents are declarative data,
validated by `apply` before anything runs; the engine executes only what
validated config permits; and schema changes must be additive only, never a
breaking change to an existing field's meaning. Engine capability may grow —
linear+fail-back today, DAG execution later per the workflow schema already
being "graph-shaped now" (v1-design.md §2) — without the schema changing
shape for existing users.
