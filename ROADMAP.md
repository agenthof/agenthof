# Roadmap

These are the directions Agenthof is building toward, grouped by horizon, not
by date. **Only the "Now" items are guarantees** — everything else is intent
that will change as the project and its users learn. Each item is a capability,
not a promise of when.

Agenthof is pre-1.0. Expect the config schema to grow (additively — existing
fields keep their meaning), and expect "Next" items to land before "Later" ones
without a fixed cadence.

## Now — shipped (pre-release)

The governed core is real and runnable today:

- **Config as law** — roles, workflows, and agents are declarative YAML,
  validated by `apply` before anything runs; every problem is reported with the
  file and entity it came from.
- **The registry & kill switch** — agents carry identity, privileges, and an
  enabled/disabled state; disabling an agent a workflow depends on fails
  loudly, naming every dependent workflow.
- **Event-sourced engine** — workflows execute with success/failure handoffs
  (linear + fail-back today) and bounded retries.
- **Hash-chained ledger, honestly scoped** — every action and every refusal is
  an event, attributed to the human who invoked it; `audit` verifies the chain
  and `audit verify --expect-head` checks it against a head you record
  off-machine. The docs are precise about what the chain does and does not
  prove.
- **Identity & RBAC** — invokers are established by a pluggable authenticator
  (`static` for dev, OIDC for production); roles gate access by group.
- **Model gateway** — agents speak logical model names resolved to any
  OpenAI-compatible endpoint, with per-role keys and budgets.
- **Execution tiers** — `contained` agents run inside Agenthof's own jailed
  runtime; `fronted` agents are any external HTTP endpoint, governed at the
  doors. The tier is recorded on every ledger event.
- **Retention** — `runs prune` ships in the core, not behind a paywall.
- **Auditable control plane** — *who applied config* and *who flipped the
  kill switch* is recorded to its own hash-chained control ledger, so "who
  changed the setup on the 14th, and who approved what's running?" is
  answerable; `audit control`, `audit verify control`, and `audit repair
  control` read, verify, and recover it.
- **Tool / MCP gateway** — an allowlisted, logged catalog: fronted agents
  reach declared MCP tool resources only through Agenthof, which authorizes
  each call against a per-agent allowlist, injects the resource credential
  (a static bearer or an OAuth `client_credentials`-minted token) the agent
  never sees, and records every call — and every denied attempt.
- **Exec gateway, attested** — allowlisted commands: a fronted agent runs an
  allowlisted command in its own operator sandbox and reports it; Agenthof
  authorizes the command against the config allowlist and records it, but
  does not run or contain it.

## Next

- **More harness adapters** — first-class support for registering and governing
  agents built on other runtimes and frameworks, not just an HTTP endpoint.

## Later

- **Governed skills & capabilities** — named capability bundles an agent may
  load, enabled or disabled per agent, workflow, or role.
- **Finer-grained privileges** — read-only vs mutating execution, and per-agent
  scoping of what an agent may touch.

## Exploring

Earlier-stage ideas we're thinking through; the least settled tier.

- **Multi-resource governance** — agents that span more than one repository or
  data source, with per-resource read/write scope and per-resource provenance.
- **Agent discovery** — surfacing agents running across an organization that
  aren't yet in the registry ("the registry as radar").
- **Stronger tamper-evidence** — signing or externally anchoring the ledger
  head so tampering is provable to a third party, not just detectable locally.

---

Have a use case or a priority you'd like to see move up? Once the project is
public, the roadmap will have a discussion thread for exactly that; until then,
open an issue.
