# Governance in action: one real agent, every door

A real model, deciding on its own which doors to open — and an audit that
shows it was governed the whole time.

## What this shows, and what it does not

Two programs are involved. `agenthof` is the governance engine
(`apply`, `run`, `audit`, `investigate`); the agent is a separate program,
`examples/langchain-agent/agent.py`, that `agenthof` calls over a socket.
`--driver llm` is the agent's flag (`python agent.py --driver llm`), not an
`agenthof` subcommand: Agenthof never embeds the agent or chooses how it
thinks (Article VII). `scripts/showcase-combined.sh` runs both sides for you;
this page still names them separately.

The scripted acceptance run (`scripts/e2e-acceptance-local.sh`) proves the
doors with an agent whose every move is fixed in advance. That is a fair proof
of the doors, but nothing in it could have gone another way. This showcase
removes the script: the same LangChain agent runs with
`python agent.py --driver llm`, and the model is handed the two door tools
plus exactly the tools its grant mirrors on the tool door. It decides, round
by round, which to call. Each model round is one governed `model_call`; each
door it opens is its own first-hand event; a door that says no records the
refusal, and the agent tells the model in fixed words that the call produced
no result. The model door already authorizes only the logical model name,
rewrites it to the provider's, and forwards the rest of a tool-calling
conversation as it is, so an agentic loop is just more governed model calls
plus the doors the model chose; no new door was needed.

What it shows: **governance and audit** — every capability the agent used
reached it through a governed, logged door (Article I), bound to the human who
started the run and, for the on-behalf-of tool, acting as that human
(Article II), with the ledger's honest, limited evidence of it (Article III).

What it does **not** show: **containment.** The compartments in this run are
host processes started by test stand-ins; nothing here proves no-egress or
that an agent could not reach a provider on its own. Those walls are the job
of the operator's runtime — the podman proofs (`scripts/e2e-refbox.sh`,
`scripts/e2e-refexec.sh`, `scripts/e2e-refbridge.sh`,
`scripts/e2e-refspawn.sh`) — and this page makes no claim about them.

**Real models vary.** A given run may take a different path, call a door
twice, or skip one. The page does not promise an outcome; it promises that
whatever the model did was governed and is on the ledger. The deterministic
proof of the loop itself is the hermetic CI run
(`scripts/e2e-acceptance-llm-local.sh`), which plays a fixed tool-calling
script against the same doors.

## How to run it

You need `go`, a Python with `examples/langchain-agent/requirements.txt`
installed (`PYTHON=...` selects it; the default is `python3`), and an
OpenAI-compatible provider that supports tool calling. The key is yours and
stays on your machine; this run cannot be part of the project's CI. Run the
commands below from the repository root (the `pip install` path is relative;
the script itself finds the repository wherever it is started from).

```sh
pip install -r examples/langchain-agent/requirements.txt
SHOWCASE_PROVIDER_BASE_URL=https://api.openai.com \
SHOWCASE_PROVIDER_KEY=sk-... \
SHOWCASE_PROVIDER_MODEL=gpt-4o-mini \
./scripts/showcase-combined.sh
```

`SHOWCASE_PROVIDER_BASE_URL` is the provider's origin without `/v1` (Agenthof
appends `/v1/chat/completions`); `SHOWCASE_PROVIDER_MODEL` is the provider's
own model name (default `gpt-4o-mini`), routed behind the logical name `fast`.
`SHOWCASE_STEP_BUDGET` optionally sets the agent's time budget for the step,
in whole seconds from 1 to 179 (default 150), so the agent stops on its own
before the step's 3-minute timeout.

The script builds `agenthof` and the stand-ins, brings up the harness, runs
one governed workflow as a verified (stub-issued) human, and prints the
engine's result, `agenthof audit <run>`, the step artifact, and
`agenthof investigate --run <run>`. It then runs `audit verify` on the parent
and on every child run, and searches every ledger, artifact, log, and
captured output for the key. Everything it started, and its working
directory, is removed when it exits, so read the output as it scrolls by.

How the key is handled: it is copied into a shell variable and removed from
the environment before any process starts — the sub-agent supervisor stand-in
launches each child agent with its own environment, so an exported key would
reach every child — and the script stops if the key is still exported under
any other name. The harness also drops any export attribute its own secret
variables might have inherited. The key then reaches the host `agenthof`
process per command only, as an assignment on that one command line, never
an exported variable. The agent never sees it; the gateway injects it
upstream.

## Reading the audit

`agenthof audit <run>` prints the parent run's events in order. This is what
each kind of line proves.

- **`model fast — … prompt / … completion tokens` (several).** One
  `model_call` per round the model took. It records the logical model and
  the token counts — not the prompt, not the reply, and **not which tools
  the model asked for**. The model's choices show up as the door events
  below, never here.
- **`exec env — exit 0 (runtime) [runtime-attested: refexec env …]`.** The
  model asked for the command; Agenthof checked it against the agent's
  allowlist; the declared runtime ran it and attested first-hand what ran.
  The event carries the argv, the exit code, the runtime's hash of the
  output (checked by Agenthof against the output it returned) and the
  runtime's attestation; the output itself is not on the ledger.
- **`tool whoami — args … (token_exchange)`.** The model called a tool on a
  per-user resource. The gateway exchanged the human's token for one
  audienced to that upstream (RFC 8693) and called it **as the human**; the
  upstream's answer names her. The agent held only its run token.
- **`tool echo — args … (static_env) [runtime-attested: refbridge …]`.** The
  model called a tool fronted by a bridge runtime, which attests first-hand
  that it ran the tool process; the bridged tool's credential was
  materialized by the bridge, never seen by the agent.
- **`spawn acceptance-worker/acceptance-sub → run r-… succeeded (depth 1) …`,
  twice.** The model asked for sub-agents; when it asks for both in one turn,
  as its instructions ask, they run in parallel. Each child is a governed
  run of its own, with its own ledger, bound to the same human and linked to
  the parent (`parent_run_id`, depth 1), and each makes its own governed
  `model_call`.
- **A refusal, if there is one** — for example `exec env refused — command
  is not on the exec allowlist`, or `spawn … → no child run refused
  (depth 1) — spawn target is not on the agent's may_spawn list`. The door
  said no and recorded it. When the exec or spawn door refuses, the agent
  tells the model `refused by policy`; when the tool door refuses, the model
  is told `the door call failed`. Either way the model decides what to do
  next, and the step may still succeed. A refusal in the audit is governance
  working, not a bug. A refused model call (`model fast refused — …`) is
  different: the model cannot be asked what to do without the model door, so
  the step fails. Not every `refused` model line is a policy decision: when
  the provider itself answers with an error, the call is recorded as refused
  too — `model fast refused — budget` for a rate limit (HTTP 429), or
  `model fast refused — upstream <code> <status text>` for any other error.
- **`ledger integrity: verified (N events)`** in the audit's header, above
  the events, and `audit verify` on each run. The chain is append-only and
  hash-chained, so it
  catches an edit, deletion, or reordering of committed events that does not
  recompute every later hash. It is tamper-evident within those limits, not
  tamper-proof; see [`concepts.md`](concepts.md#the-ledger) for the honest
  limits.

`investigate --run <run>` then shows the same story as one timeline across
the whole tree: the parent's events, and each child's events indented under
them and tagged with `parent=<run>`, every line naming the human who started
the run.

## What is first-hand and what is asserted

The step **artifact** — the `model: called exec`, `exec: …`, `tool whoami: …`,
`spawn: succeeded …` lines the agent returns, ending with the model's own
`model: …` answer — is the **agent's own summary**. It is useful for reading
along, and the agent collapses each leg onto one line so no upstream text can
forge an extra line, but it is produced by the untrusted agent and proves
nothing by itself. The evidence is the **door events on the ledger**, written
by Agenthof and the runtimes first-hand: the `exec` event with the runtime's
attestation, the `tool_call` events with their auth mode and the bridge's
attestation, the `spawn` events and the children's own ledgers, and the
`model_call` events. If the artifact and the ledger ever disagreed, the
ledger is what happened. Do not read the artifact as proof.

## Any framework, the same doors

The agent is organized in two layers. A **framework-neutral door layer** —
plain Python over `httpx` and the official `mcp` SDK — speaks the wire
contract in [`agent-protocol.md`](agent-protocol.md): the exec and spawn
doors as JSON over the gateway URL, the tool door as a standard
streamable-HTTP MCP session, and the model door as an OpenAI-compatible
endpoint. The two door tools the model is offered, `exec(command)` and
`spawn(role, workflow, input)`, and the discovery of the granted MCP tools
with their schemas live in that layer. The **LangChain shell** is thin: it
points `ChatOpenAI` at the model door, binds those tool specs, and carries
each model turn. Porting to another framework means rewriting only the
shell; the doors govern every framework identically because they all speak
the same contract. LangChain is one example here; for first-class support
for registering and governing agents built on other runtimes and frameworks,
see "More harness adapters" on the [roadmap](../ROADMAP.md#next).

See also: [`examples/langchain-agent/README.md`](../examples/langchain-agent/README.md)
for the agent's flags and behaviour, [`lifecycle.md`](lifecycle.md) for the
life of a run, and the four life-of-a-door pages linked from the
[README](../README.md#documentation).
