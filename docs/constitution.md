# The Agenthof Constitution

This document states the invariants every change to Agenthof must honor.
Where it and any other document disagree, this constitution wins.

## Article I — Containment by governance

Capability reaches an agent only through governed, logged doors: the tool/MCP
gateway, the exec gateway, and the model gateway. Where a door injects a
credential, the agent never holds it — today the tool/MCP gateway, which
injects a resource credential per call. The model gateway is reserved: until
the fronted model proxy lands, a fronted agent's model access is arranged by
its operator, outside Agenthof. Allowlisted commands run in the operator's
sandbox and each is recorded — attested by the agent today; Agenthof records
but does not run or contain them, and enforced execution is reserved. The
agent runs in an operator-provided sandbox. That sandbox's network and exec
confinement is required, and Agenthof does not verify it. No change may add
an unmediated network call, or a credential stored where an agent's config or
runtime can read its value.

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
SHA-256 of the exact bytes of its predecessor's line (genesis: empty
string), and `audit` verifies the chain. The chain makes accidental
corruption — and any edit, deletion, or reordering of committed events that
does not recompute every later link — detectable. It does not by itself
detect truncation of the tail or wholesale regeneration of the file; those
are detectable only against a chain head recorded off the machine; Agenthof
prints the control-log head after each append but does not store it. No Agenthof document may describe the ledger as
tamper-proof. Artifact bodies never enter the ledger — only a SHA-256 hash
and a preview of at most 200 characters; bodies live in a separate,
prunable store. Secrets and full artifact bodies are never written to an
event, under any circumstance.

## Article IV — Compliance floors (US / AU / EU)

Retention controls ship in the open-source core (`runs prune
--older-than <d>`) — never gated behind a commercial tier. Audit logging and
basic RBAC are permanently free in the open-source core; they are not, and
will not become, paid features. The FIPS build path (Go's native FIPS 140-3 mode, `GOFIPS140`)
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
config file.

Authorization is default-deny: a role grants access only to invokers whose
groups appear in its declared `allowed_groups`; the value `["*"]` is the
explicit marker for a role open to any authenticated invoker; a role that
declares no access floor at all is rejected at `apply`, never treated as open.

Schema changes must be backward compatible: additive only,
never a breaking change to an existing field's meaning. Engine capability
may grow (e.g. linear+fail-back today, DAG execution later) behind schemas
that do not change shape for existing users. Control-plane actions (apply, and the enable/disable kill switch) are themselves recorded in a hash-chained control ledger.

## Article VII — Scope discipline

The product is the registry, roles, and audit trail — the governance layer.
Sandboxes, gateways-as-proxies, and agent execution frameworks are consumed
as dependencies, not rebuilt as product surface. A change that reimplements
functionality already solved by an off-the-shelf facade is out of scope
unless that facade cannot satisfy Articles I through VI.

## Amendment

These articles change only by an explicit commit that edits this file, with
a commit message stating which article changed and why. No article is
amended implicitly by a code change, a config default, or an edit to any
other document. If another document and this constitution ever diverge,
this constitution is binding until amended.
