# Concepts

This page explains the ideas behind Agenthof: what the pieces are, why they
are arranged this way, and which guarantees are enforced by code rather than
by convention. For the field-level mechanics of configuration, see
[`docs/reference/config.md`](reference/config.md). For the invariants every
change to Agenthof must honor, see [`docs/constitution.md`](constitution.md);
where this page and the constitution disagree, the constitution wins.

## The shape: roles, workflows, agents

Agenthof fixes a one-way reference direction: **roles → workflows → agents →
tools**. A role owns one or more workflows; a workflow is composed of agents
that hand off to each other on success and bounce back on failure; an agent
is deliberately unconstrained in kind — a retrieval agent, a coder, and a
classifier are all the same schema.

The **registry** is not a folder on disk but a behavior: the loaded,
validated union of the `agents/`, `workflows/`, and `roles/` config
directories plus `gateway.yaml`. Reference resolution, enabled/disabled
state, and privileges all live there. `apply` validates everything at once
and reports every problem it finds, each naming the file and the entity it
came from. Disabling an agent that a workflow still depends on is itself a
validation failure, and it names every dependent workflow. That is
deliberate: governance you can see.

## Two planes

The runtime separates a control plane from a data plane.

- **Control plane** — `registry/` (load, validate, resolve, enable and
  disable, privileges), `engine/` (event-sourced execution), `identity/`
  (authenticators and the delegation binding), and `audit/` (ledger write
  and read). This is the layer that decides what is allowed to run, and
  records what did.
- **Data plane** — `gateway/`: it resolves logical model names to real
  endpoints and provisions per-role keys and budgets, and it carries the
  schema slot reserved for a V2 `tools:` block.

The agent runtime in `agentrt/` — which materializes ADK-Go agents from
registry entries, exposes the jailed tool catalog, and fronts external
agents through the adapter — is driven by the control plane, and is where
an agent's actual work happens.

## The three governed surfaces

Three gateways are first-class in the design from the start, on the
principle that designing them in is not the same as building them now:

1. **Model gateway** — the data plane for model calls. It is a
   LiteLLM-class facade: something to run, not to rebuild. It holds
   per-role virtual keys with budgets.
2. **Tool/MCP gateway (V2)** — reserved as a schema slot (`tools:` in
   `gateway.yaml`) but not built in V1. V1 ships a jailed tool catalog
   instead — list, search, read, edit, write, and no exec — as part of the
   agent runtime.
3. **Control tower** — the platform itself: the config directory, `apply`,
   and the registry. Unlike the other two this is not a network facade; it
   is the config, validation, and registry path described above.

## Execution tiers

Every agent runs under one of two execution tiers, chosen by its registry
entry's `execution` field: `contained` (the default — an empty `execution`
means `contained`) or `fronted`.

**`contained`** is the `agentrt/` path: the agent is materialized as an
ADK-Go agent node running inside Agenthof's own runtime, behind the jailed
tool catalog. This is containment *by construction* — a jailed workspace
(path-confined, symlink-hardened, no dotfile or VCS-metadata access) and no
exec tool, so there is nothing for the agent to escape through. A contained
agent may not declare an `endpoint`, and its `model` is resolved and checked
against `gateway.yaml` the normal way (see
[`docs/reference/config.md`](reference/config.md#model)).

**`fronted`** is the adapter path: the agent is an external HTTP service
reachable at its registry entry's `endpoint` — any agent, in any language or
framework, that serves one HTTP route. Because the agent's own code runs
outside Agenthof, its internals cannot be contained the way a contained
agent's can. Instead it is **governed at the doors it has to pass through to
act as an agent of the platform**: the same identity, ledger, and — where
applicable — gateway machinery every agent is subject to. Put differently, a
fronted agent's internals are *attested*, not *enforced*. Agenthof governs
what crosses the boundary — the call in, the result out, and the identity
and ledger entries around it — not what the external service does
internally. Concretely, the call in carries the run's identity as
`X-Agenthof-*` request headers (see
[`docs/lifecycle.md`](lifecycle.md#how-an-agent-actually-runs-two-tiers) for
the list) — attested like the rest of the boundary, not enforced. A fronted
agent may not declare `tools` (tools are a
contained-runtime capability), and its `model` routing is not checked, since
it is not calling through Agenthof's model gateway the way a contained agent
does (see
[`docs/reference/config.md`](reference/config.md#execution) for the exact
rules `execution` and `endpoint` interact under). A fronted agent's failure
is not special-cased: a timeout or error is an ordinary step failure with
the same fail-back semantics as any other step.

The tier is not only a validation-time concept. It is **recorded on the
registry entry** (the agent's `execution` field, as loaded from config) and
**stamped on every step event the engine writes to the ledger** — the same
value, carried on `step_started`, `step_succeeded`, and `step_failed`. That
means `audit` can show, for each step of a run, which guarantee applied to
it: whether the step ran inside Agenthof's own containment, or was handed
off to an externally fronted, doors-governed agent. No cross-referencing
against the config required.

## Identity: three identities per action

Every action carries three identities.

1. **Invoker** (human) — subject, issuer, and groups, established by a
   pluggable authenticator: `static` for development (`--as user@example.com`
   or the OS user; the ledger records `method: asserted`) or `oidc` for
   production, which validates a JWT from any OIDC identity provider and
   records `method: oidc`.
2. **Agent** (workload) — its entry in the registry. The registry is the
   agent's identity provider: no agent gets an external identity object,
   which makes an agent identity free, instant, and revocable with
   `enabled: false`.
3. **Delegation binding** (per run) — `invoker → role → workflow → agent →
   run-id`, stamped on every ledger event and every gateway call.

Taken together this is an inversion of the usual arrangement. Agents draw
identity from the registry rather than from an external identity provider,
external credentials live only in gateways and never in an agent, and
attribution rides the ledger rather than the credential: authenticate as the
machine, attribute to the human, per action. It is also what keeps the
integration surface small — only mature, universally supported standards are
load-bearing, namely OIDC login and machine-to-machine client credentials.
Emerging agent-identity standards (RFC 8693 token exchange, SPIFFE/WIMSE,
identity-provider agent-SSO products) are optional federation upgrades, never
prerequisites for a release.

## Containment

Agents get no raw network access, no shell, and no ambient credentials.
Capability reaches an agent only through governed, logged doors: the model
gateway (metered and budgeted), the tool catalog (allowlisted and logged;
the tool gateway in V2), and a jailed workspace (path-confined,
symlink-hardened, with no dotfile or VCS-metadata access). Every one of
those doors writes to the ledger. No change may add an agent-reachable exec
tool, an unmediated network call, or a credential stored where an agent's
config or runtime can read its value.

## The ledger

Every action an agent takes, and every refusal, is an event in the ledger,
and every event carries the full delegation binding. The ledger is
hash-chained: each event carries the SHA-256 of the exact bytes of its
predecessor's line (genesis: empty string), and `audit` verifies the chain.
The chain's guarantee is honest but limited: it catches accidents (a disk
error, a botched migration) and lazy tampering — any edit, deletion, or
reordering of committed events that does not recompute every later hash.
It does not by itself catch a careful attacker who truncates the tail and
re-forges a new, internally consistent chain from that point; checking for
that requires a chain head recorded somewhere off the machine, which
Agenthof does not store. `audit verify --expect-head` performs exactly
that check when handed a previously recorded head — the limitation is that
Agenthof itself keeps no such record, not that the check is unavailable.
Once an attacker has write access to the ledger file, nothing recorded
after the point of compromise can be trusted on the strength of the chain
alone. No Agenthof document may describe the ledger as tamper-proof.
Artifact bodies never enter the append-only ledger — only a SHA-256 hash
and a preview of at most 200 characters, with bodies in a separate,
prunable store. Secrets and full artifact bodies are never written to an
event, under any circumstance.

Refusals and failures are different things, and the distinction is visible
in the ledger:

- A **refusal** happens before any execution and is recorded as a single
  `run_refused` event. An invalid or expired token, an invoker whose groups
  do not satisfy the role's `allowed_groups`, and a run against invalid
  configuration are all refusals — denials are audit events too, not silent
  exits.
- A **step failure** is ordinary execution that did not succeed, including
  a fronted agent's timeout and a model-gateway rejection such as an
  exceeded budget. It is handled by the workflow's fail-back graph rather
  than refused; only once bounces are exhausted does the run finish with
  `workflow_finished{status: failed}`. The whole chain stays in the ledger,
  so a failed run is as legible afterwards as a successful one.

### Control-plane audit

`apply` and the `registry enable|disable` kill switch write to a second,
separate ledger — the **control log** — rather than to any run's own event
log: control actions are not tied to a run, and "who applied this config"
or "who disabled the coder agent, and when" must stay answerable even when
no run ever happens. It uses the same append-only, hash-chained mechanism
described above, with the same honest limits: it catches suppression or
alteration of a committed record, not a truncated tail or a wholesale
re-forge from a clean point, which is detectable only against a head
recorded off the machine. Agenthof prints that head after every successful
append — `control head: seq=N sha256=<hex>` — but does not store it; saving
it somewhere off-machine (a CI log, a git note, a message) is what makes
`agenthof audit verify control --expect-head <hex>` meaningful later. See
[`docs/reference/config.md`](reference/config.md#control-plane-cli) for the
exact flags and exit codes.

The default path is `.agenthof/control.jsonl`, resolved relative to the
current working directory the same way key and workspace paths are — run
these commands from the repository root, or pass `--control-log`
explicitly. It is never written under `--log-dir`, and `runs prune` skips
it and any `*.torn-<timestamp>` repair fragment (below) by name — a control
log saved under a different name inside `--log-dir` is not protected this
way. Nothing rotates or seals the control log today; it is kept in full,
indefinitely, as the compliance record, not run ephemera. Its invoker
subjects are personal data like any other identity the ledger records, so
the self-hosting operator is the data controller for it, same as for the
run ledger.

Every control event carries the invoker and a witness — the local OS user
and hostname, captured independently of the asserted identity, the same
oidc-is-evidence / asserted-is-a-claim / witness-is-corroboration framing
as [identity](#identity-three-identities-per-action) above. A successful
`apply`, a rejected `apply`, and a successful flip each also carry a
`config_hash` — over the applied or rejected bytes, or the config as it
reads immediately after the flip — so "who approved what's running", or
what a rejected config looked like, needs no cross-referencing. (Because
enabling or disabling an agent rewrites that agent's YAML formatting, the
hash on a flip event changes on every flip, even one that leaves the
enabled bit as it was.) A denial is an event too: a failed token, a
rejected config, and an unknown agent name are all recorded, each with a
reason code. The one exception is a control log that itself cannot be
written — torn or broken — where the refusal is loud (naming the repair
command to run) but unrecorded, since there is no known-good chain left to
safely record it against. A second, narrower exception exists on
`enable`/`disable`: if the enabled bit is flipped but computing the fresh
hash or appending the event then fails, the command prints "state changed;
event NOT recorded" and exits nonzero — the one case where the registry's
state and the control log can disagree, and it is treated as an incident
to investigate by hand, not a bug the ledger papers over.

A torn control log — the tail of an interrupted write — is recovered with
`agenthof audit repair control`. The damaged bytes are moved, verbatim, to
a sibling `<log>.torn-<timestamp>` file, never pruned automatically and
kept as the sole remaining copy of what was there; the live log is
truncated back to its last valid record; and the repair itself is appended
as an ordinary, attributed control event. That last step **taints the
ledger permanently** — repair restores availability, it does not erase
what happened — and `agenthof audit verify control` reports that taint
from then on, on every future invocation, cleared by nothing. A chain
break (a well-formed record that disagrees with its neighbor, rather than
an interrupted write) is not something repair can fix at all; only a torn
tail is recoverable this way.

## Config is law

Roles, workflows, and agents are declarative data, validated by `apply`
before anything runs, and the engine executes only what validated config
permits — no hidden capability, and no implicit behavior that cannot be
traced to a config file. Schema changes are additive only, never a breaking
change to an existing field's meaning. Engine capability may still grow —
linear plus fail-back today, DAG execution later, since the workflow schema
is already graph-shaped — without the schema changing shape for existing
users.
