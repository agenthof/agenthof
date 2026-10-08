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
  `repair`, `provision`, and `prune` its groups may perform — each named explicitly, no wildcard,
  nothing by omission — and a caller no role grants is refused and the
  refusal recorded (a refused ledger repair is printed, not recorded, since
  the ledger it would go to is the damaged one).
  Those decisions are made against the **installed** configuration — the
  snapshot the last successful `apply` put in place — never against the
  change being proposed, so a change cannot grant its own applier the right
  to make it; the first `apply` on a fresh control root bootstraps, and
  `audit control` says so. A configuration that grants `apply` to nobody is
  rejected rather than installed.
- **`run` executes the installed configuration** — a run (command line or
  `serve`) resolves the snapshot the last successful `apply` or kill-switch
  flip installed beside its control ledger, never the configuration
  directory, and stamps that snapshot's hash; nothing installed is a recorded
  refusal that names the `apply` to run. The kill switch re-installs the
  configuration with the one bit flipped — the directory is untouched, and an
  `apply` re-asserts what the directory declares. `audit <run-id>` names the
  install a run executed under, `apply` or flip. The installed bytes are verified
  against the pointer before a run or a kill-switch flip reads them; the
  store's pointer is not yet chained into the ledger.
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

## Next

- **Streamed model usage and Agenthof-side budgets** — record token counts
  from a streamed completion, and cap spend inside Agenthof rather than only
  at the upstream gateway. A per-role list of models, and OAuth-protected
  model providers, sit with this.
- **More harness adapters** — first-class support for registering and governing
  agents built on other runtimes and frameworks, not just an HTTP endpoint.
- **Every control-plane action authorized and recorded** — bring the last
  operator actions that still bypass it — provisioning a role's model-gateway
  key, pruning run ledgers — under the same default-deny `control:`
  authorization, and record each, so no control action is unauthorized or
  unlogged.
- **Signed, verifiable configuration snapshots** — the installed-config
  snapshot gains an operator signature and a tamper-evident pointer, is
  verified against that signature when a run reads it (today the bytes are
  checked against the pointer's hash only), and can be
  pulled and checked over the API — so a run's configuration is provably the
  one the operator installed.
- **More confinement backends** — the reference runtime's confinement becomes a
  selection seam with OS-native backends beyond rootless podman (for example
  macOS Seatbelt, Linux Landlock), chosen per host with a fail-closed default
  and the applied tier named in the ledger — an honest contract, since a
  shared-kernel sandbox is not a container is not a VM.

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
- **Stronger tamper-evidence** — signing or externally anchoring the ledger
  head so tampering is provable to a third party, not just detectable locally.

---

Have a use case or a priority you'd like to see move up? Open an issue — the
roadmap will grow a discussion thread for exactly that.
