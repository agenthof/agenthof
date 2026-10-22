# The Agenthof Constitution

This document states the invariants every change to Agenthof must honor.
Where it and any other document disagree, this constitution wins.

## Article I — Containment by governance

Capability reaches an agent only through governed, logged doors: the tool/MCP
gateway, the exec gateway, and the model gateway. Where a door injects a
credential, the agent never holds it. The tool/MCP gateway injects a resource
credential per call. The model gateway injects the per-role provider key, so
a fronted agent reaches models through Agenthof and never holds that key.
Allowlisted commands run in a trusted operator-side runtime — the reference
one is `refexec`, a rootless-podman supervisor on the operator's host — that
runs each command on the agent's behalf and attests it first-hand, and each
is recorded. There is no agent-asserted exec: an agent's own report of a
command it ran is not a record, and a call to report one is refused at the
door and that refusal recorded. First-hand exec is a core capability.
Agenthof runs no commands itself — exec containment is the operator's
runtime's job, not Agenthof's — so Agenthof-run exec stays rejected, and the
first-hand record trusts that runtime the way the tool door trusts a declared
bridge; no document may describe either record as tamper-proof. The
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

The external credentials Agenthof injects live only in its gateways, never in
agent config or agent runtime state; config may reference an env-var name,
never a secret value. Credentials Agenthof does not govern — e.g. a key a
non-conforming agent obtains outside Agenthof's gateways — are the
operator's, outside Agenthof. Only mature, universally supported standards are
load-bearing: OIDC login and M2M client-credentials. Emerging agent-identity
standards (token exchange, SPIFFE/WIMSE, IdP agent-SSO products) are optional
federation upgrades, never prerequisites for a release.

## Article III — The ledger

Every action an agent takes, and every refusal (invalid identity, exceeded
budget, disabled agent), is an event in the ledger. Every event carries the
full delegation binding. The ledger is hash-chained: each event carries the
SHA-256 of the exact bytes of its predecessor's line (genesis: empty
string), and `audit` verifies the chain. The chain makes accidental
corruption — and any edit, deletion, or reordering of committed events that
does not recompute every later link — detectable. It does not by itself detect truncation of the tail or wholesale regeneration of the file; those are detectable only against a chain head recorded off the machine. Agenthof prints the control-log head after each append and does not store it itself. Where a control root declares `anchor: tlog`, the operator may pin the control-log head to an external append-only transparency log (`audit anchor`); the ledger then records which head was anchored, which log entry holds it, the log's proof of inclusion, and which log key signed for it — never a credential, never a secret. A head so anchored is tamper-evident and independently verifiable: whoever holds the anchor's reference and the log's public key can check, against the log's own proof, that exactly that head was entered, with the integration time the log records; `audit verify control` fails on any anchor the chain records whose head it no longer reproduces, and a reference held off the machine is checked with `--expect-head seq:hash`. The guarantee is bounded, and Agenthof states the bounds: records appended after the last anchor are evidenced only by the chain until the next anchor; a verifier that takes the log's key from the log, or the log's address from the root being verified, trusts what it was handed and is not independent; a log the verifier cannot reach, or a log key other than the one the verifier trusts, is reported as unverifiable, never as tampering; and the ephemeral key that signs a log entry proves nothing beyond the log's requirement for one. Where a control root declares `sink: worm`, sealing a segment also writes the sealed segment's exact bytes to write-once storage the operator brings, under a compliance-mode retention lock the storage provider enforces, and the seal does not complete until that copy is confirmed; the seal record names where the copy is and the date its lock lasts to. Within that period the protected copy of a sealed segment cannot be deleted, altered or shortened by any storage operation, whoever issues it, the account's owner included; the provider's one escape is closing the account, which is outside Agenthof's view and is not silent — this is the one claim for which the words write-once and immutable are used, and they describe that copy alone, for that period alone, on the strength of the provider's compliance mode, which Agenthof does not run and verifies only by reading what the provider reports. `audit verify control` fails on a sealed segment whose protected copy is missing, locked less strongly or less long than the seal recorded, or holds other bytes, and on an object the sink holds for the ledger that no verified local segment accounts for; a sink the verifier cannot reach is reported as unverifiable, never as tampering. The bounds are stated: the active segment, every local file, and any segment sealed before the root declared the sink are ordinary files with no protected copy; a consistent rewrite of the whole local set is caught by the sink only where the rewritten set no longer accounts for what the sink holds, and by an anchored head checked against a reference held off the machine; and when the retention period ends the copy is a file like any other. No Agenthof document may describe the ledger as tamper-proof. Artifact bodies never enter the ledger — only a SHA-256 hash
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

Authorization is default-deny, at both the run boundary and the control
plane: a role grants access only to invokers whose groups appear in its
declared `allowed_groups`; the value `["*"]` is the explicit marker for a role
open to any authenticated invoker; a role that declares no access floor at all
is rejected at `apply`, never treated as open.
A grant that names a set of reachable capabilities — invokers, tools,
executables — declares which ones; the widest such set is an explicit marker
(a role's `["*"]`, a tool grant's `tools: ["*"]`), and a grant that names none is
rejected at `apply`, never widened to the maximum. One grant is shaped
differently because its set is internal and fixed: `control:` is an optional
grant over a fixed, enumerable set of control operations; it carries no widest
marker, an absent key means no control permission (not "names none"), and a
present-but-empty `control: []` is rejected at `apply` like any other grant
that names none. Where a shipped shape conflicts with this rule it is retired
by amendment — rejected at `apply` with its replacement named — never by
silently changing what it means.

Schema changes must be backward compatible: additive only,
never a breaking change to an existing field's meaning. Engine capability
may grow (e.g. linear+fail-back today, DAG execution later) behind schemas
that do not change shape for existing users. Control-plane actions (apply, the enable/disable kill switch, control-ledger repair, provisioning a role's provider key, pruning run ledgers and artifacts under retention, anchoring the control-log head to an external log, and sealing the control ledger's active segment, and restoring a sealed segment from its protected copy) are themselves authorized — default-deny, against the `control` operations a role declares — and recorded in a hash-chained control ledger. Anchoring is such an action and not a vouch: it appends to the ledger and publishes to a log outside it, attributed on the ledger to the invoker, so it is granted by a role's `anchor` operation and recorded as its own event, whether it succeeded or failed. Sealing is such an action too: it closes the segment of the control ledger that is being written and opens the next, and the chain continues unbroken across that boundary — the first record of the new segment carries the hash of the sealed segment's last record, and sequence numbers continue — so the ledger stays one chain however many segments hold it; it is granted by a role's `seal` operation and recorded as its own event under the invoker, whether it succeeded or failed, a successful seal as the last record of the segment it closes. Agenthof never writes new content into a sealed segment. A sealed segment is a file like any other, and no document may describe it as immutable, write-once or tamper-proof; where the root declares `sink: worm`, the seal's protected copy of it is the one exception, exactly as Article III bounds it, and writing that copy is part of the seal — granted by the same `seal` operation and attributed on the same record. Restoring a sealed segment from its protected copy writes back exactly the bytes the chain commits to and taints nothing; it is granted by a role's `repair` operation and recorded as its own event under the invoker. Reading the installed configuration out of the control plane,
to distribute it to the execution points that enforce it, is authorized the
same way — the `pull` operation, which a grant of `apply` includes — and, as a
read, is not recorded. The operator's signature over an installed
configuration — made by the host at install time, or again by `config sign`
— is a derivation of the install the control ledger already records, gated by
possession of the signing key on that host, as the key itself is; it attests
that record, mints no policy and binds to no role, and so is neither
authorized against a role nor separately recorded. The engine executes an
installed configuration only when the control ledger vouches for it — the last
install the ledger records is that configuration; a verdict that the ledger does
not vouch for it is a recorded run refusal. Where a control-plane action is
authorized against an installed configuration, that configuration must be one
the control ledger vouches for — the same vouch — and a verdict that the
ledger does not vouch for it is a refusal, recorded wherever the action itself
is recorded; control-ledger repair and restore are the exceptions: they are authorized
against the installed configuration's byte-verified roles without consulting
the ledger it exists to repair, and its refusal is printed, not recorded.
Vouching for the installed configuration — recording, for the snapshot the
pointer already names and whose bytes verify, the install event the control
ledger lacks — is a host-local recovery act of the same class as the first
apply: permitted without a role grant, for any identity the host resolves,
and always recorded as its own event under the invoker, so that the ledger's
account of what is installed is restored only by a visible, attributable
act; it validates nothing beyond the bytes and that some role still grants
`apply` to a named group, and the default-deny control gate is what bounds a
configuration no apply validated. Where an execution point
pins an operator public key, it executes an installed configuration only if
that configuration's signature verifies under the pinned key and the install is
of the ledger, and not below the version, the point last accepted; a verdict
against the configuration is a recorded run refusal. The point's record of the
installs it has accepted is its own state — a derivation of verifications it
performed — not a control-plane action: it mints no policy, binds to no role,
and is neither authorized against a role nor recorded in the
control ledger.

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
