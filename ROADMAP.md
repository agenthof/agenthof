# Roadmap

These are the directions Agenthof is building toward, grouped by horizon, not
by date. **Only the "Now" items are guarantees** — everything else is intent
that will change as the project and its users learn. Each item is a capability,
not a promise of when.

Agenthof is pre-1.0. Expect the config schema to grow (additively — existing
fields keep their meaning); where a shipped shape conflicts with a
constitutional rule it can be retired by amendment, rejected at apply with its
replacement named. Expect "Next" items to land before "Later" ones without a
fixed cadence.

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
- **Completeness beside integrity** — `audit <run-id>` and `audit verify`
  report a second line: whether the ledger accounts for itself — every
  step's final event carries the number of door calls its gateway
  admitted, and exactly that many door events are recorded inside the step
  — with `GAP`, `UNTERMINATED` and `no claim` verdicts and their own exit
  codes (`11`, `12`), rolled up across a run's spawned children. Judged
  against the gateway's own count: it catches an honest source's
  accidental loss, not a dishonest source, and says so.
- **Identity & RBAC** — invokers are established by a pluggable authenticator
  (`static` for dev, OIDC for production); roles gate access by group.
- **Fronted agents** — every agent is an external HTTP endpoint, governed at
  the tool/MCP, exec, model, and sub-agent-spawn doors. The agent runs in an operator-provided
  sandbox; that sandbox's network and exec confinement is required, and
  Agenthof does not verify it. `execution: fronted` (the default when the
  field is empty) is stamped on every step event.
- **Isolated agents — reference sandbox runtime** (`deploy/refbox`) — runs a
  fronted agent with **no network at all**, reaching Agenthof only over a
  bind-mounted Unix socket, so credential-starvation and no-egress hold *by
  construction* on the operator's host. It is the operator's sibling runtime —
  Agenthof still executes nothing — and its guarantees and limits are stated
  plainly, not assumed.
  Two reference images run there today: a Go echo agent and a Python
  LangChain agent whose model call reaches Agenthof through the gateway
  socket in that same directory — a framework agent governed with no
  provider key and no network. That same LangChain agent can also drive the
  tool/MCP (via the official MCP SDK), exec, and sub-agent-spawn doors
  through that one gateway — a single framework agent exercising every door.
  With `--driver llm` that agent lets a real model choose the doors itself;
  [`docs/showcase.md`](docs/showcase.md) shows how to run it against your own
  provider and read the audit.
- **Model gateway** — a fronted agent reaches models through Agenthof. The
  per-role provider key is injected and is not passed through to the agent.
  The logical model is authorized, the provider model is rewritten on the
  way out, and each call is a `model_call`. Non-streaming calls record token
  counts. A provisioned role key lets the upstream gateway enforce
  `budget_usd_month`. Streamed calls are recorded without token counts.
  Agenthof does not itself cap spend.
- **Retention** — `runs prune` ships in the core, not behind a paywall; it is authorized against the installed roles' `prune`
  grant and recorded in the control ledger.
- **Auditable control plane** — *who applied config* and *who flipped the
  kill switch* is recorded to its own hash-chained control ledger, so "who
  changed the setup on the 14th, and who approved what's running?" is
  answerable; `audit control`, `audit verify control`, and `audit repair
  control` read, verify, and recover it. `agenthof investigate` merges this
  control ledger with the run ledgers into one timeline — human-readable or
  `--json` — each source carrying its own verification verdict.
  Those control actions are themselves **authorized, default-deny**: a
  role's `control:` grant names which of `apply`, `enable`, `disable`,
  `repair`, `provision`, `prune` and `pull` its groups may perform — each named explicitly, no wildcard,
  nothing by omission except that a grant of `apply` includes `pull` — and a caller no role grants is refused and the
  refusal recorded (a refused ledger repair is printed, not recorded, since
  the ledger it would go to is the damaged one).
  Those decisions are made against the **installed** configuration — the
  snapshot the last successful `apply` put in place — never against the
  change being proposed, so a change cannot grant its own applier the right
  to make it; the first `apply` on a fresh control root bootstraps, and
  `audit control` says so. That authorization read verifies the snapshot's
  bytes against the pointer and requires the control ledger to record the
  pointer as its last install — a pointer it does not vouch for refuses every
  control action, recorded (`audit repair control` excepted: it verifies the
  bytes but does not consult the ledger it repairs; a pull, being a read,
  answers a retryable `503` and records nothing). `config vouch` puts an
  install whose record never landed back on record without touching the
  configuration — a recovery act open to any identity on the host, always
  recorded as its own event. A configuration that grants `apply` to no named
  group is rejected rather than installed.
- **`run` executes the installed configuration** — a run (command line or
  `serve`) resolves the snapshot the last successful `apply` or kill-switch
  flip installed beside its control ledger, never the configuration
  directory, and stamps that snapshot's hash; nothing installed is a recorded
  refusal that names the `apply` to run. The kill switch re-installs the
  configuration with the one bit flipped — the directory is untouched, and an
  `apply` re-asserts what the directory declares. `audit <run-id>` names the
  install a run executed under, `apply`, flip, or vouch. The installed bytes
  are verified against the pointer before a run, a control command's
  authorization, or a kill-switch flip reads them, and `run` and `serve`
  execute — as the control commands authorize against — only a snapshot the
  control ledger records as its last install: a pointer the ledger does not
  vouch for (re-aimed by hand, a dropped-in snapshot, an install whose record
  never landed) is a recorded refusal, and a damaged ledger refuses runs until
  it is repaired. What remains
  undefended is a consistent rewrite of both the pointer and the ledger, which
  a head saved off the machine catches today (`audit verify control
  --expect-head`), a pinned key refuses unless the writer also holds the
  signing key, and external anchoring to a transparency log (`anchor: tlog`)
  proves to a third party.
- **Tool / MCP gateway** — an allowlisted, logged catalog: fronted agents
  reach declared MCP tool resources only through Agenthof, which mirrors a
  whole resource (written `tools: ["*"], mode: read-write` — every-tool
  access is always an explicit marker, never what a resource id or a missing
  `mode` grants by omission), only the tools an agent's grant names, or —
  with `mode: read-only` — only the tools the operator lists as
  `read_only_tools` (the upstream's own read-only hint does not decide this),
  authorizes each call against that per-agent
  allowlist, injects the resource credential (a static bearer, an OAuth
  `client_credentials`-minted token, or — on behalf of the invoking human —
  a per-user token exchanged from their verified OIDC token via RFC 8693)
  the agent never sees, and records every
  call — and every denied attempt.
  A stdio-only MCP server is governed the same way through `deploy/refbridge`,
  a reference bridge that fronts it over a Unix socket only Agenthof dials,
  starts it once per session with a clean environment plus the injected
  credential, respawns it when a rotating credential changes, and ends it
  with the session. Agenthof still runs nothing — and because the bridge is
  the party that runs the server, it attests first-hand on every call what
  it ran, which the ledger records on the `tool_call` event when the
  resource declares `runtime: refbridge`.
- **Exec gateway, first-hand** — allowlisted commands, run by a trusted
  operator-side runtime. The agent asks, and `deploy/refexec` — a reference
  operator-side runtime on the host — runs the allowlisted command in a
  rootless-podman compartment with no network on a workspace shared with the
  agent's compartment, and attests what ran; Agenthof authorizes the command
  against the config allowlist and records that account on the `exec` event.
  Agenthof itself runs no command, and an agent's own report of one is
  refused and recorded. Historical agent-reported exec events in old ledgers
  still verify and render.
- **Sub-agent spawn, isolated per child** — a fronted agent asks its per-run
  gateway for a governed child run of a `{role, workflow}` its `may_spawn`
  lists, and gets the child's result back as a hash and a preview. Each
  child is a full run under the same human — its own ledger, linked to the
  parent by run id and depth — nested and parallel within three required
  caps (`max_depth`, `max_parallel`, `max_total_spawns`) plus an optional
  static cycle check at `apply`, and torn down with its parent's step;
  `investigate --run` shows the tree. A child runs in compartments of its
  own: `deploy/refspawn`, a reference operator-side supervisor on the host,
  gives it one workspace volume, one rootless-podman refbox compartment per
  agent in its workflow, and one `refexec` bound to that volume, and
  removes them in order when the child is over. With no supervisor a child
  is refused, never run beside its parent. Agenthof itself still runs
  nothing.
- **Served runs and a read API** — `agenthof serve` hosts concurrent
  governed runs behind an HTTP API where every call carries the human's
  own OIDC token: start a run, poll it, read its ledger with an honest
  integrity verdict, fetch the same audit text the CLI prints, and run
  `investigate` across both ledgers. A served run records where the
  request came from (`origin`) as provenance beside the verified
  identity. `run`, `audit` and `investigate` take `--server`, so the CLI
  is a client of the same API.
  Configuration changes over the same API: `apply --server` posts the
  configuration with a compare-and-swap on the installed hash, is
  authorized against the installed roles, and is recorded with where it
  came from.
  An execution point pulls the installed configuration over the same API
  (`GET /v1/config`, `config pull --server`): authorized by a `pull` grant
  (or `apply`, which includes it), served only when its bytes hash as the
  installed pointer and the control ledger records the install that put it
  there, re-applies to the same hash, and — as a read — is not recorded.
- **Operator-signed configuration snapshots** — with an Ed25519 key on the
  install host (`config keygen`; the operator keeps the private key there),
  every install signs the configuration over a payload binding its hash to the
  control ledger's identity, the install's version, and its time. `serve`
  returns that signature on the pull and verifies it against the bytes as it
  serves them, answering only when the ledger vouches for the pointer **and** a
  matching signature verifies; `config pull` names the signer. Signing is
  opt-in; `config sign` (re)signs an install. It is evidence of origin, as
  strong as the private key's custody on the host — not a vault.
- **Verifying the installed configuration against a pinned key** — an execution
  point pins the operator's public key (`agenthof run --verify-key <path>`, or
  `verify.pub` beside the control ledger), and `run` and `serve` verify the
  installed configuration's signature against it **before executing** — refusing
  an unsigned, wrong-key, tampered, or (by a persisted staleness floor) replayed
  or rolled-back older install; a held configuration lock answers a retryable
  busy, not a refusal. Pinning is opt-in and fail-closed: with a key pinned,
  verification is mandatory. It is tamper-evident at the execution point, not a
  vault — it catches a tampered or partially-restored installed store, but not a
  restore of the whole control root from backup (which restores the floor too);
  exclude `verify.floor` from the backup set if it must survive one. The
  signature is bound to the control root that made the install and does not
  travel with a pull: a configuration pulled and applied on another host is
  signed afresh there (or not at all), so a central operator key pinned on that
  host would refuse it. Today the key a host pins is the one its own installs
  are signed with; carrying the operator's signature along the pull path is the
  next step (below).
- **External anchoring of the control-ledger head** — `agenthof audit anchor`
  pins the current head into a transparency log the operator names
  (`anchor: tlog` in `integrity.yaml`, signed with an ephemeral per-anchor key),
  and `audit verify control` checks every recorded anchor against the live
  chain — failing only on a head the chain no longer reproduces, and reporting
  an unreachable log or a rotated key as *unverifiable*, never as tampering.
  This makes a determined whole-root rewrite — the one gap the local hash chain
  cannot close — provable to a third party.
  `agenthof investigate` shows each anchor's facts and the verdict
  `audit verify control --offline` reaches, decided offline from the stored
  proof, on its event in the timeline and the
  `investigate/1` document, locally and over `serve` — informational, with
  `audit verify control` as the gate. The guarantee is bounded and stated
  plainly: between anchors the head rests on the chain alone (cadence is the
  operator's cron); independence holds only when the log's key and address do
  not both come from the root being verified; and a public-good log exposes
  opaque head hashes and their timing. `sink: worm` (below) keeps a protected
  copy of each sealed segment; a non-erasable storage sink for the whole
  ledger (`sink: external`) and `anchor: signed` remain reserved.

- **Sealing and rotating the control ledger** — `agenthof audit seal` closes the
  active log into a sealed segment and opens a fresh one, so a long-running
  control ledger becomes an ordered set of sealed segments plus a live active
  segment — read, verified, and appended as one continuous hash chain. The seal
  is itself a recorded, authorized control action, and the rotation is
  crash-safe: an interrupted seal is *completed* by re-running `audit seal`,
  never left in a broken state. `audit verify control` verifies every segment as
  one chain and reports a rotation caught mid-flight distinctly from tampering;
  `audit repair control` recovers a torn tail of the active segment and refuses
  to touch a sealed segment — a cleanly interrupted rotation it declines, naming
  `audit seal` as the way to finish it. An incomplete rotation blocks new
  writes; reads of the ledger continue. A ledger that is never sealed behaves
  exactly as before. The limit is stated plainly: a sealed segment is a regular
  file whoever owns the host can still rewrite — the chain detects a dropped,
  duplicated, reordered, or inconsistently edited segment, not a consistent
  rewrite of the whole set. Pinning sealed segments into write-once storage
  ships as `sink: worm`, built on this foundation: each seal also writes the
  sealed segment's exact bytes to S3 Object Lock storage the operator brings,
  under a compliance-mode retention lock the provider enforces, and does not
  complete until that copy is confirmed; `audit verify control` checks every
  protected copy, `audit restore control` puts a damaged sealed segment back
  from it, and `audit restore control --rebuild` reconstructs the whole sealed
  set and its manifest from the sink. The bound is stated plainly: the active
  segment and every local file stay ordinary files, and the copy is protected
  for the retention period alone, by the provider's compliance mode. `sink:
  external` remains reserved.

## Next

- **Streamed model usage and Agenthof-side budgets** — record token counts
  from a streamed completion, and cap spend inside Agenthof rather than only
  at the upstream gateway. A per-role list of models, and OAuth-protected
  model providers, sit with this.
- **More harness adapters** — first-class support for registering and governing
  agents built on other runtimes and frameworks, not just an HTTP endpoint.
- **Every control-plane action over the API** — provisioning a role's
  model-gateway key and pruning run ledgers are authorized and recorded from
  the command line today; the same two operations over the API, under the same
  default-deny `control:` authorization, and a structured record of what a
  prune removed, are still to come.
- **The operator's signature at the edge** — a consuming edge that obtains a
  configuration by `config pull` verifies the *operator's* signature against its
  pinned key before running it — whether it executes the pulled bytes directly
  or applies them to its own root (today the signature stays with the signing
  root: `config pull` names the signer but does not carry the signature, an
  edge's own `apply` signs with the edge's key, and so an execution point
  verifies only installs made on its own root) — so the edge distribution path
  is provably the operator's, end to end. On its own root an execution point
  already executes only the install its control ledger records (above); what
  that cannot catch — a consistent rewrite of pointer and ledger together — is
  what external anchoring of the head (`anchor: tlog`, above) is for.
- **More confinement backends** — the reference runtime's confinement becomes a
  selection seam with OS-native backends beyond rootless podman (for example
  macOS Seatbelt, Linux Landlock), chosen per host with a fail-closed default
  and the applied tier named in the ledger — an honest contract, since a
  shared-kernel sandbox is not a container is not a VM.
- **Anchoring a run's audit, not only the control ledger** — external anchoring
  (`anchor: tlog`) today pins the *control* ledger's head to a transparency log
  the operator does not control; the same corroboration for each **run's** audit
  would make a run's receipt checkable against something off the machine, not
  only as an unedited local chain. A run of all-`succeeded` events is only as
  independent as the box it was written on until its head is anchored.

## Later

- **Governed skills & capabilities** — named capability bundles an agent may
  load, enabled or disabled per agent, workflow, or role.
- **Finer-grained privileges** — per-agent scoping of what an agent may
  touch, beyond today's per-tool, read-only, exec, and spawn grants, plus
  per-object ownership in RBAC (an object's creator-owner alongside the admin).

## Exploring

Earlier-stage ideas we're thinking through; the least settled tier.

- **Multi-resource governance** — agents that span more than one repository or
  data source, with per-resource read/write scope and per-resource provenance.
- **Agent discovery** — surfacing agents running across an organization that
  aren't yet in the registry ("the registry as radar").

---

Have a use case or a priority you'd like to see move up? Open an issue — the
roadmap will grow a discussion thread for exactly that.
