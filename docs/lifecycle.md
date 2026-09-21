# The life of a run

This page follows a single `agenthof run` from the command you type to the
audit trail you read back — every subsystem it touches, in the order it touches
them. If [`concepts.md`](concepts.md) is the *nouns* (what the pieces are) and
[`constitution.md`](constitution.md) is the *law* (the invariants), this page is
the *verbs*: how the pieces move together over time.

Everything below describes what ships **today**. Where something is reserved for
a later version, it says so — only shipped behavior is a guarantee.

## The command

```
agenthof run software-engineer fix-bug --input "fix the login bug" --as dana@example.com
```

That one line sets five things in motion:

- **the invoker** — the human the run is attributed to (`dana@example.com`);
- **the role** — `software-engineer`, which owns workflows and gates who may use them;
- **the workflow** — `fix-bug`, an ordered list of steps;
- **the agents** — each step names one, run either inside Agenthof or fronted over HTTP;
- **the ledger** — where every step and every refusal is recorded as it happens.

## The journey at a glance

```
  agenthof run
      │
      ▼
  1. Who is asking?     authenticate  ──►  Invoker {subject, issuer, method, groups}
      │
      ▼
  2. Are you allowed?   registry gate  ──►  no ──►  run_refused  (recorded, then stop)
      │ yes
      ▼
  3. Start the run      create run-id + delegation binding; write workflow_started
      │
      ▼
  4. For each step:     step_started ─► run the agent ─► step_succeeded / step_failed
      │                          │
      │                          ├─ contained: ADK agent in a jailed workspace
      │                          └─ fronted:   external HTTP service (attested)
      │                          (a model call gets its key from the gateway here)
      │
      ▼
  5. Finish             workflow_finished { succeeded | failed }
      │
      ▼
  6. Read it back       agenthof audit <run-id>  ──►  who asked → what ran → integrity
```

## 1. Who is asking? (authentication)

The first thing that happens is establishing *who the human is* — the
**invoker**. There are two ways in:

- **Development:** `--as dana@example.com` (or your OS user if omitted). Groups
  can be asserted with `--groups`, but these are **self-asserted and not
  verified** — dev only. The ledger records the method as `asserted`.
- **Production:** `--token <id-token>` (or the `AGENTHOF_TOKEN` env var). The
  token is a real OIDC ID token, verified against your identity provider (issuer
  and client id come from the environment). The ledger records the method as
  `oidc`.

Either way the result is one small, immutable value — the `Invoker`
(`subject`, `issuer`, `method`, `groups`) — and that is *all* that flows
downstream. If a token fails verification, the run never starts: it is recorded
as a refusal and stops. (The token itself is verified and then discarded; it is
never stored and never written to the ledger.)

## 2. Are you allowed? (the registry gate)

Before anything runs, the engine asks the **registry** a series of yes/no
questions, in order:

1. Is the role in the registry?
2. Is the workflow in the registry?
3. Does the role own that workflow?
4. If the role restricts access (`allowed_groups`), do the invoker's groups
   include one of them?

The config must also be valid — `apply`-style validation runs first, and
invalid config is itself a refusal. Any "no" produces a single **`run_refused`**
event and the run stops. Refusals are audit events, not silent exits: a denial
is as visible in the ledger as a success.

> Note (today's behavior): a role with **no** `allowed_groups` is invokable by
> anyone. If you want a role gated, give it an `allowed_groups` list. Making
> unlisted roles fail-closed by default is a planned change, not current
> behavior.

If every check passes, the engine mints the **run-id** and the **delegation
binding** — `invoker → role → workflow → agent → run-id` — and from here on
that binding is stamped on *every* event the run writes. This is the heart of
the model: **authenticate as the machine, attribute to the human, per action.**

## 3–4. Running the workflow, step by step

The engine writes `workflow_started`, then walks the workflow's steps in order.
For each step it writes `step_started` (naming the step, the agent, and the
agent's execution tier), runs the agent, and then records the outcome.

### How an agent actually runs: two tiers

Every agent runs under one of two tiers, and **which one is stamped on every
step event**, so an audit shows exactly what guarantee applied:

- **`contained`** (the default) — the agent is materialized as a Google-ADK
  agent *inside Agenthof's own runtime*, confined to a **jailed workspace**
  (path-confined, symlink-hardened, no dotfile or VCS-metadata access) and given
  **only its file tools** — list, search, read, edit, write. There is no shell
  and no raw network. This is *containment by construction*: there is no door
  for the agent to escape through because none was built.
- **`fronted`** — the agent is an external HTTP service Agenthof calls out to.
  Its internal code runs outside Agenthof, so it cannot be contained; instead it
  is **governed at the doors it must pass through** — the call in, the result
  out, and the identity and ledger entries around it. A fronted agent is
  *attested, not enforced*.

Two executors ship for the contained tier: the default **`echo`** executor,
which runs fully offline with no model and no credentials (great for trying the
flow), and the **`adk`** executor, which runs a real model-backed agent.

### The life of a credential (model-backed runs)

When a contained agent needs to call a model, it does **not** hold an API key.
Instead:

1. the **gateway** resolves the agent's logical model name to a real endpoint
   and the calling **role's** provisioned key;
2. that key is injected into the model client's transport at the moment of the
   call;
3. the agent uses the model — and **never sees the key**. No tool returns it,
   there is no shell or env access, and it is never placed in the agent's prompt.

The credential lives in the door, not in the agent. This is the same pattern
every future external resource will use: the credential is held and injected by
a governed gateway, and the human is attributed through the ledger rather than
through the credential.

> Reserved for later: reaching **other** secured resources (databases, APIs,
> MCP servers) goes through a **tool/MCP gateway** with the same
> hold-and-inject shape. It is a reserved slot in the schema, **not built in the
> current version**. The model gateway is the only resource door today.

### Success, artifacts, and handoff

On success the engine writes `step_succeeded`. If the step produced an artifact,
the artifact **body** is written to a separate, prunable store, while the ledger
records only a **SHA-256 hash and a short preview (at most 200 characters)** —
never the full body. A named artifact is then handed to later steps as prior
context. The engine moves to the next step.

### When a step fails

A step that doesn't succeed produces `step_failed`, and the workflow's
**fail-back** kicks in: control bounces to the step's `on_failure` target (or
the previous step), up to a bounce cap (default 2). Each bounce is a
`bounced_back` event. When the bounces are exhausted — or there is nowhere to
bounce — the run ends as `workflow_finished { failed }`. A *configuration* error
is different: it can't be fixed by retrying, so it fails the run immediately
without bouncing.

Note the distinction the ledger preserves: a **refusal** happens *before*
execution (bad identity, failed authorization, invalid config); a **failure** is
ordinary execution that didn't succeed. Both are fully recorded.

## 5. Finish

When the last step succeeds, the engine writes `workflow_finished { succeeded }`
and the run is done. The whole story — who asked, what ran, what each step
touched, what it cost to get there — now lives in the run's ledger.

## The record (the life of a ledger event)

Every event above is one line in the run's append-only ledger, and every event
carries two things: the **full delegation binding** (so any single line tells
you who the run belongs to) and the **hash of the previous line** (genesis: the
empty string). That chain is what lets `audit` detect tampering.

Be precise about what the chain guarantees. It catches **accidents** (a disk
error, a botched edit) and **lazy tampering** — any edit, deletion, or
reordering that doesn't recompute every later hash. It does **not**, by itself,
catch a careful attacker who truncates the tail and re-forges a consistent chain
from that point; catching that needs a chain head recorded off the machine
(`audit verify --expect-head`), which Agenthof does not store for you. The
ledger is honestly tamper-**evident**, not tamper-**proof**, and no Agenthof
document should call it otherwise.

## 6. Reading it back

```
agenthof audit <run-id>
```

`audit` reads the run's ledger, verifies the chain, and prints the story in
plain form: the run id, workflow and role; **who invoked it** (subject, method,
issuer); the final status; and a **ledger integrity** line — `verified (N
events)`, or `TORN` (the last record was cut off mid-write), or `BROKEN at event
N` (a link doesn't match). Then it lists the timeline: workflow started, each
step started/succeeded/failed, any bounces, and how the run finished. That is
the full loop — *who asked → what ran → what it touched → whether the record can
be trusted* — with no cross-referencing required. When the run's
`workflow_started` carries a config hash, `audit <run-id>` also prints one
more line naming the control-plane `apply` that put that config in place (or
saying plainly that none is on record, or that the control ledger isn't
available right now) — see
[`reference/config.md`](reference/config.md#control-plane-cli) for the exact
wording.

### Investigating across runs

A single run's audit trail answers "what happened in this run." For "what
happened across everything, in this window" — an incident spanning several
runs and the control plane together — there's `agenthof investigate`. It
merges the control log and every run log under `--log-dir` into one
time-ordered timeline, filterable by time window, invoker, agent, outcome,
run, or config hash, rendered as plain text or (`--json`) the stable
`investigate/1` contract. Each source's own integrity is surfaced right
alongside the events it contributed — a torn or broken log still contributes
its valid prefix rather than silently dropping evidence. See
[`reference/config.md`](reference/config.md#control-plane-cli) for the full
flag and exit-code reference.

## What ships today vs what is reserved

| Shipped today | Reserved for later |
|---|---|
| `echo` (offline) and `adk` (model-backed) executors | tool/MCP gateway for non-model resources |
| model gateway with per-role keys + budgets | agent auth to IdP-protected resources (M2M / on-behalf-of) |
| `contained` and `fronted` execution tiers | enforced capabilities for fronted agents |
| hash-chained ledger + `audit` / `audit verify` | multi-resource / cross-repo scope |
| RBAC by group; linear workflow + fail-back | DAG workflows |
| cross-run + control incident timeline (`investigate`) + config-join on `audit <run-id>` | SIEM / multi-org investigation at scale |

Only shipped behavior is a guarantee.

## See also

- [`concepts.md`](concepts.md) — the pieces and why they're arranged this way.
- [`constitution.md`](constitution.md) — the invariants every run must honor.
- [`reference/config.md`](reference/config.md) — every field that shapes a run.
- [`quickstart.md`](quickstart.md) — build it and run one yourself.
