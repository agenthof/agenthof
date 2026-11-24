# The life of an ask

One question in plain language, from the command you type to the answer and
the receipt you read back. `ask` is the orchestrator: it does not answer
anything itself. It asks an installed classifier which of its agents fits your
request, runs that agent as a governed child, and hands you its answer with a
receipt of how it was produced.

`ask` is a trusted command, not a contained agent. Like
[`run`](lifecycle.md), it establishes a governed run of its own from the
installed configuration and is attributed to a human invoker. Unlike `run`, it
chooses the workflow for you, by asking a classifier — and every agent it ends
up running, the classifier included, is a [spawn](lifecycle-spawn.md): a child
run in its own compartment. So this page is `run` and `spawn` composed, with
two things of its own on top — the menu it offers the classifier, and the
receipt it prints.

For the subsystems underneath, see [`lifecycle.md`](lifecycle.md) (the run
`ask` establishes), [`lifecycle-spawn.md`](lifecycle-spawn.md) (how the
classifier and the leaf are run and confined), and
[`lifecycle-enroll.md`](lifecycle-enroll.md) (how the agents it routes to were
installed). For an executable proof — a real two-agent ask under macOS
Seatbelt, with the installed configuration denied to the compartments — see
[`scripts/e2e-ask-seatbelt.sh`](../scripts/e2e-ask-seatbelt.sh), run with
`make acceptance-ask`.

## The command

```
agenthof ask "summarise what changed in the payments service this week"
```

Flags precede the prompt, which is the single trailing argument:

```
agenthof ask --as dana@example.com --yes "…"
```

The prompt is exactly one positional argument. A flag written *after* the
prompt is a usage error, never folded into the prompt — so a `--token` or
`--as` placed after the prompt can neither leak into the model nor be silently
dropped. A prompt that itself begins with `-` must be preceded by `--`.

Only the answer is written to stdout. Every status line, refusal, and the
receipt go to stderr, so a piped `ask … | …` carries the answer alone.

## The journey at a glance

```
  agenthof ask "<prompt>"
      │
      ▼
  1. Who is asking?        authenticate  ──►  Invoker {subject, issuer, method, groups}
      │
      ▼
  2. What is installed?    vouch the installed snapshot (not --config)  ──►  invalid / none ──► refused
      │
      ▼
  3. Are you allowed?      registry gate on {orchestrator, ask}  ──►  no ──► ask_refused (recorded, stop)
      │ yes
      ▼
  4. What can I offer?     project the orchestrator's may_spawn into a menu  ──►  empty ──► say so, no spawn
      │
      ▼
  5. Which one fits?       spawn the classifier (router-chat) with {menu, prompt}
      │                       └─ answer read from the artifact store by digest: a pick, or null
      ▼
  6. Act on the pick       null / off-menu ──► print what I can do (succeed)
      │                     on-menu, ungrounded ──► confirm (or --yes), else stop
      │ confirmed
      ▼
  7. Run the agent         spawn the leaf as a governed child  ──►  read its answer from the store by digest
      │
      ▼
  8. Answer + receipt      answer to stdout; receipt (subtree rollup) to stderr, after the run's terminal
```

Steps 5 and 7 are ordinary spawns — the classifier and the leaf each get a
compartment, a ledger, and the full door treatment described in
[`lifecycle-spawn.md`](lifecycle-spawn.md). Everything else is `ask`'s own.

## Trusted, but bounded by configuration

`ask` is core command code, so it is trusted to read the answer back and to
mediate the confirmation — things a contained agent could not be trusted to do.
What it is *allowed* to route to is not a matter of trust but of configuration:
the installed `orchestrator` agent's
[`may_spawn`](reference/config.md#may_spawn) list is its whole authority. It
can start the agents on that list and nothing else, and the spawn gate
re-checks every one of them against that list (step 5 and step 7 both go
through it), so a thin or even a forged menu changes nothing about what may
actually run.

The orchestrator agent's own `endpoint:` is never dialled — `ask` drives its
children directly rather than running the orchestrator as a workflow step, so
the endpoint may be any placeholder. The one caveat: `run orchestrator ask`
*would* front that endpoint and hand whatever listens there the orchestrator's
`may_spawn` authority, so the orchestrator agent is meant to be run only
through this command.

## What `ask` checks before it routes

1. **Who is asking.** The invoker is resolved exactly as at `run`: a verified
   `--token` (OIDC) when present, otherwise the `--as` identity (and its
   self-asserted `--groups`, which are a development convenience, never
   verified). A token that fails verification is a recorded refusal.
2. **What is installed.** `ask` runs the **installed snapshot** — the
   configuration vouched under the control ledger — never the raw `--config`
   directory. A missing, invalid, or unverifiable snapshot is refused, and the
   message points at `agenthof apply`. Config is law: `ask` obeys what was
   installed, not what is lying in a source directory.
3. **Are you allowed.** The orchestrator run passes the same registry gate
   every run passes — the `orchestrator` role must exist, own the `ask`
   workflow, and admit the invoker's groups — before any spawn. Without this
   the role's `allowed_groups` would be decorative. A no is recorded as a
   refusal with the role's classifying reason, and nothing is spawned.

Each refusal is written to a ledger of its own before `ask` stops, so even a
request that never routes anywhere leaves an auditable record.

## The menu and the classifier

The menu offered to the classifier is the orchestrator's `may_spawn` list,
projected in order, each entry carrying its `{role, workflow}` and a
description drawn from the workflow (or its first agent). The classifier's own
target is never a menu choice. Separately, the **invoker-admitted subset** of
that menu — the entries whose role would admit *this* invoker — is what the
"here is what I can do" listing shows; the gate, not the listing, is the
authority over any pick.

The classifier is the installed `router-chat` agent, and `ask` spawns it like
any other child: through the spawn gate, subject to the same `may_spawn` check,
caps, and parent-ledger record. It is told the menu and the prompt under the
keys its signed card fixes:

```json
{ "menu": [ { "role": "...", "workflow": "...", "description": "..." } ],
  "utterance": "<the prompt>" }
```

Its answer is read from the artifact store by the digest its spawn recorded
(the answer body never rides the ledger — see Article III below). The answer is
either a pick — `{ "role": "...", "workflow": "..." }` — or the literal `null`
when nothing fits. A classifier spawn that did not succeed, or an answer that
is neither a complete pick nor `null`, is an error: `ask` stops rather than
guess a route. The classifier runs contained and its text is untrusted, so a
pick that names a target not on the offered menu is recorded with a fixed
reason — never the classifier's own words — and treated as "nothing fits".

## The confirmation gate

When the pick is on the menu, `ask` decides whether the answer needs a human's
go-ahead before it runs the agent. The test is the picked workflow's agents:
an agent is waved through only if its configuration declares
[`grounding: grounded`](reference/config.md#grounding) (it answers from your
data); any other value, an unset value, or an agent the registry cannot find
means the answer could be the model's own invention, and `ask` confirms.

`--yes` skips the question. Without it, on a terminal, `ask` asks `[y/N]` and
runs only on an explicit yes; an interrupt ends the prompt as a decline rather
than blocking. With no terminal to ask on and no `--yes`, an ungrounded pick is
refused with a message telling you to re-run with `--yes` — consent is never
assumed from a closed input.

## Running the agent, and reading the answer

The chosen leaf is spawned through the very same gate the HTTP `/spawn` door
uses — one shared authorization-and-spawn path, so the door and `ask` cannot
drift apart in what they permit. The leaf runs as a governed child in its own
compartment ([`lifecycle-spawn.md`](lifecycle-spawn.md)), and its spawn result
carries the **digest** of its final artifact and a capped preview — never the
answer body.

**Article III holds here as everywhere: the answer body never travels on a
ledger or in a spawn result.** `ask` reads the full body from the host's
content-addressed artifact store, by the digest the spawn recorded. A leaf that
produced no artifact, an artifact missing from the store, and an empty answer
are each a recorded failure, not a blank success.

## The orchestrator's own ledger

Because `ask` spawns, it keeps a ledger of its own, exactly as a spawning agent
does — so each child it starts is recorded on a parent. That ledger accounts
for itself the way any governed run's does:

- a `workflow_started` that promises door accounting;
- **one** step window (`orchestrate`) that every spawn sits inside;
- a step terminal carrying the count of door calls the gate admitted;
- a `workflow_finished` whose status matches the step's.

There is a single exit after `workflow_started`, and every path reaches it, so
the step terminal and the workflow terminal always agree. The result is that
`agenthof audit <ask-run>` reports the orchestrator run **complete**, not a
false gap — the flagship command audits clean like any other run.

`ask` fails closed on any parent-ledger write error: if the record of a spawn
could not be written, that spawn's output is never used and the run ends with a
ledger-write failure. A governed child never runs unrecorded with its output
released.

## The answer and the receipt

The answer goes to **stdout**. When stdout is a pipe or a file it is
byte-exact. When stdout is a terminal, control characters other than newline
and tab are stripped first, so a contained leaf's answer cannot drive the
cursor, recolour, or clear the screen to forge the trust signals around it.
(Graphic runes — accented letters, CJK, non-breaking spaces — are kept, so real
text in any language is untouched.)

The **receipt** follows on stderr, after the run's own terminal event is on the
ledger, so its verdicts cover the whole run. It is a rollup of the run subtree —
the orchestrator's ledger and every child's — in two deliberately separated
parts:

- **Enforced by construction**, read from the run ledgers: the invoker (shown
  `verified` only for an OIDC token, otherwise marked caller-asserted and not
  verified); for each child, its containment tier as the supervisor reported it
  and, for an enrolled agent, the measured artifact; the door calls each child
  run fired; and per ledger, the hash-chain integrity and the completeness
  verdict. It carries digests and verdicts only — never an artifact body.
- **Agent-asserted**, declared in configuration or by the caller and **not
  checked** by Agenthof: whether the leaf agent calls its answers grounded or
  model-generated.

The receipt reuses the honest wording of
[Article III](constitution.md): the chain links each record to the one before
it, so edits show up; it is evidence, not a guarantee against someone who
controls the ledger. "Door calls" count every door a run opened, a refused or
denied call included.

## Containment of the installed configuration

The classifier and the leaf run in compartments the operator's supervisor
creates ([`lifecycle-spawn.md`](lifecycle-spawn.md)). On podman they have no
host filesystem access by construction. On macOS Seatbelt a compartment can
read most of the host unless a subtree is denied, so the operator denies the
control root — where the installed snapshot, the operator signing key, and the
run ledgers and artifact store live — through the supervisor's
[`deny_read`](../deploy/refspawn/README.md) list. The `acceptance-ask` proof
asserts exactly this: a compartment cannot read the installed `gateway.yaml`,
while an ordinary host file stays readable, so the deny is specific. This is
containment *by configuration* on Seatbelt, not by construction — stated
plainly where it is claimed.

## Limits, stated plainly

- **`ask` itself is trusted and not contained.** It is core command code
  running as the operator; the containment boundary is around the agents it
  spawns, not around `ask`. What it may route to is bounded by the
  orchestrator's `may_spawn`, re-checked at the gate on every spawn.
- **The classifier's text is untrusted.** A pick is honoured only if it names
  an offered menu entry; anything else is recorded as misbehaviour with a fixed
  reason and treated as "nothing fits". The classifier never widens what can
  run.
- **Grounding is an operator's declaration, not a measurement.** The confirm
  gate and the receipt both trust the agent's configured `grounding`; Agenthof
  does not verify that a "grounded" agent actually answered from your data. The
  grounded-answer path — retrieval agents whose grounding is earned — is
  reserved for a later increment.
- **The answer's integrity rests on the store and the recorded digest.** `ask`
  trusts that the artifact at the recorded digest is the leaf's answer; the
  spawn subtree's ledgers are the evidence for how that answer was produced.
- **The terminal defence stops escape-sequence forgery, not a look-alike.**
  Stripping control characters prevents a leaf from driving the cursor to
  overwrite the receipt; it cannot stop a leaf from emitting plain text that
  merely reads like a receipt. The answer is on stdout and the genuine receipt
  on stderr, so a pipe separates them and a terminal still prints the real
  receipt, after a blank line, below the answer.

## What ships today, and what is reserved

Today `ask` is single-shot: one prompt, one classification, one leaf, one
answer, one receipt. The classifier is `router-chat` and the routable agents
are whatever the operator installed and listed in the orchestrator's
`may_spawn`. Reserved for later, and marked as such wherever it matters: a
multi-turn/interactive client over the same orchestrator; grounded retrieval
agents (so "grounded" in the receipt becomes an earned property, not only a
declaration); and richer menus. Only the shipped behaviour is a guarantee.

## See also

- [`lifecycle.md`](lifecycle.md) — the life of a run, which the orchestrator and every child it spawns are.
- [`lifecycle-spawn.md`](lifecycle-spawn.md) — how the classifier and the leaf are run, confined, and recorded.
- [`lifecycle-enroll.md`](lifecycle-enroll.md) — how the agents `ask` routes to were installed from a signed card.
- [`constitution.md`](constitution.md) — Article II (three identities), Article III (the ledger is limited evidence).
- [`reference/config.md`](reference/config.md#may_spawn) — `may_spawn`, `grounding`, the gateway `spawn` caps, `spawn_supervisor`.
- [`deploy/refspawn/README.md`](../deploy/refspawn/README.md) — the reference supervisor and its `deny_read` config isolation.
