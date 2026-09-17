# The Agenthof Constitution

This document states the invariants every change to Agenthof must honor. It
is distilled from the design spec (`docs/design/v1-design.md`). Where the two
disagree, this constitution wins.

## Article I — Containment by construction

Agents get no raw network access, no shell, and no ambient credentials.
Capability reaches an agent only through governed, logged doors: the model
gateway, the tool catalog (tool gateway in V2), and a jailed workspace
(path-confined, symlink-hardened, no dotfile or VCS-metadata access). No
change may add an agent-reachable exec tool, an unmediated network call, or a
credential stored where an agent's config or runtime can read its value.

## Article II — Identity

Every action carries three identities:

1. **Invoker** (human) — subject, issuer, and groups, established by a
   pluggable authenticator (`static` for dev, `oidc` for production).
2. **Agent** (workload) — its entry in the registry. The registry is the
   agent's identity provider; no agent gets an external identity object.
3. **Delegation binding** (per run) — `invoker → role → workflow → agent →
   run-id`, stamped on every ledger event and every gateway call.

External credentials live only in gateways, never in agent config or agent
runtime state; config may reference an env-var name, never a secret value.
Only mature, universally supported standards are load-bearing: OIDC login
and M2M client-credentials. Emerging agent-identity standards (token
exchange, SPIFFE/WIMSE, IdP agent-SSO products) are optional federation
upgrades, never prerequisites for a release.

## Article III — The ledger

Every action an agent takes, and every refusal (invalid identity, exceeded
budget, disabled agent), is an event in the ledger. Every event carries the
full delegation binding. The ledger is hash-chained: each event carries the
SHA-256 of its predecessor's serialized line (genesis: empty string), so
tamper-evidence is a provable property, not a claim. Artifact bodies never
enter the immutable ledger — only a SHA-256 hash and a preview of at most 200
characters; bodies live in a separate, prunable store. Secrets and full
artifact bodies are never written to an event, under any circumstance.

## Article IV — Compliance floors (US / AU / EU)

Retention controls ship in the open-source core (`runs prune
--older-than <d>`) — never gated behind a commercial tier. Audit logging and
basic RBAC are permanently free in the open-source core; every competitor
paywalls these, and that contrast is load-bearing for the project, not
incidental. The FIPS build path (Go's native FIPS 140-3 mode, `GOFIPS140`)
must never be broken by a dependency; a dependency bump that breaks it is a
regression, not a tradeoff. The self-hosting customer is the data
controller for any personal data in the ledger — Agenthof does not act as a
data processor by default and does not assume that role silently.

## Article V — License

The core is Apache-2.0, forever. No relicensing to a BUSL-style or
source-available license, and no clause that restricts who may run, fork, or
compete with the software. Commercial offerings may exist alongside the
core (multi-tenancy, SSO enforcement, SIEM export, managed cloud) but never
by removing rights the core already grants.

## Article VI — Config is law

Roles, workflows, and agents are declarative data, validated by `apply`
before anything runs. The engine executes only what validated config
permits — no hidden capability, no implicit behavior not traceable to a
config file. Schema changes must be backward compatible: additive only,
never a breaking change to an existing field's meaning. Engine capability
may grow (e.g. linear+fail-back today, DAG execution later) behind schemas
that do not change shape for existing users.

## Article VII — Scope discipline

The product is the registry, roles, and audit trail — the governance layer.
Sandboxes, gateways-as-proxies, and agent execution frameworks are consumed
as dependencies, not rebuilt as product surface. A change that reimplements
functionality already solved by an off-the-shelf facade is out of scope
unless that facade cannot satisfy Articles I through VI.

## Amendment

These articles change only by an explicit commit that edits this file, with
a commit message stating which article changed and why. No article is
amended implicitly by a code change, a config default, or a design-doc
edit alone. If the design spec and this constitution ever diverge, this
constitution is binding until amended.
