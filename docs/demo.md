# The Demos

This document walks through four scripted demonstrations of Agenthof's core
governance capabilities: CONFIG (agent registry management), AUDIT (run
traceability and integrity), GOVERNANCE (role-based access control and
budgeting), and INVESTIGATE (incident investigation across the control plane
and every run).

## Part 1: CONFIG Moment — Registry Management & Kill Switches

Demonstrates how roles, workflows, and agents are defined in YAML and validated on apply; and how the kill switch prevents invalid configurations from running.

### 1.1 Apply and verify the registry

```bash
cd <path-to-your-clone>
./agenthof apply --as dana@example.com --config examples/config
```

Expected output:
```
registry ok: 5 agents, 2 workflows, 2 roles
control head: seq=1 sha256=<hex>
```

The `control head` line is the control ledger recording this apply, attributed
to `--as` (read it with `audit control`, shown at the end of Part 1); `seq`
increments with each control action and the hash varies. The registry now
includes:
- 5 agents: planner, coder, reviewer, categorizer, reconciler
- 2 workflows: fix-bug, reconcile-lite
- 2 roles: software-engineer, accountant

### 1.2 Edit an agent instruction and re-apply

Edit `examples/config/agents/reviewer.yaml` and change the instruction:

```bash
# Before:
# instruction: |
#   You are a review agent. Judge the patch against the plan.

# After:
# instruction: |
#   You are a review agent. Check the patch carefully, naming any issues.
```

Then re-apply:

```bash
./agenthof apply --as dana@example.com --config examples/config
```

Expected output (the `seq` has advanced — this is the second control action):
```
registry ok: 5 agents, 2 workflows, 2 roles
control head: seq=2 sha256=<hex>
```

Configuration changes are validated immediately; no stale configs can propagate.

### 1.3 Test the kill switch: disable an agent and watch apply fail

Disable the coder agent:

```bash
./agenthof registry disable coder --as dana@example.com --config examples/config
```

Expected output (the kill-switch flip is recorded in the control ledger,
attributed to `--as`):
```
agent coder disabled
control head: seq=3 sha256=<hex>
```

Now try to apply:

```bash
./agenthof apply --as dana@example.com --config examples/config
```

Expected output:
```
workflows/fix-bug.yaml: fix-bug: workflow "fix-bug" depends on agent "coder", which is disabled in the registry
```

The registry refuses to load because fix-bug depends on coder, which is now disabled. The error names the broken workflow immediately. The rejected apply is itself recorded in the control ledger (outcome `rejected`, with the hash of the rejected config) — denials are audit events too.

Re-enable the agent:

```bash
./agenthof registry enable coder --as dana@example.com --config examples/config
```

Expected output:
```
agent coder enabled
control head: seq=5 sha256=<hex>
```

Verify the registry is healthy again:

```bash
./agenthof apply --as dana@example.com --config examples/config
```

Expected output:
```
registry ok: 5 agents, 2 workflows, 2 roles
control head: seq=6 sha256=<hex>
```

### 1.4 Read the control ledger: who changed what, and when

Every `apply` and kill-switch flip above was recorded, attributed, and
chained. Read the control-plane audit trail:

```bash
./agenthof audit control
```

Expected output (abbreviated):
```
control ledger — 6 events

  seq 1  <ts>  config applied — dana@example.com (asserted)
  seq 2  <ts>  config applied — dana@example.com (asserted)
  seq 3  <ts>  disabled agent coder — dana@example.com (asserted)
  seq 4  <ts>  config rejected — dana@example.com (asserted)
  seq 5  <ts>  enabled agent coder — dana@example.com (asserted)
  seq 6  <ts>  config applied — dana@example.com (asserted)
control ledger integrity: verified (6 events)
```

Verify the control chain, and pin it against a head you recorded off the
machine (the head is printed after each control action but never stored —
paste it into CI logs, a git note, or a message):

```bash
./agenthof audit verify control --expect-head <hex>
```

Exit codes: `0` clean · `1` torn/broken/missing · `3` tainted (a repair
happened) · `4` head mismatch. The chain is append-only and tamper-evident,
not tamper-proof — it detects alteration of committed records, and, against a
recorded head, truncation or re-forge; see
[`docs/concepts.md`](concepts.md#the-ledger) for the honest limits.

---

## Part 2: AUDIT Moment — Run Traceability & Integrity

Demonstrates how every run is attributed to an invoker, and the audit trail captures identity, execution steps, and artifact integrity (SHA256).

### 2.1 Run a workflow as an identity and audit it

Run the fix-bug workflow as dana@example.com:

```bash
./agenthof run software-engineer fix-bug \
  --input "fix the login bug" \
  --as dana@example.com \
  --executor echo \
  --config examples/config
```

Expected output:
```
workspace: .agenthof/workspaces/<unix-nano>
run r-<run-id> finished: succeeded
```

Copy the run ID (e.g., `r-9e31cf9b`). Then audit the run:

```bash
./agenthof audit r-9e31cf9b
```

Expected audit output:
```
run r-9e31cf9b — fix-bug (role software-engineer)
invoked by dana@example.com (asserted, issuer local)
status: succeeded
ledger integrity: verified (8 events)

  08:57:52  workflow started
  08:57:52  step plan (agent planner) started
  08:57:52  step plan succeeded — artifact 511878f2: [planner] fix the login bug
  08:57:52  step code (agent coder) started
  08:57:52  step code succeeded — artifact 565dfc2c: [coder] fix the login bug
  08:57:52  step review (agent reviewer) started
  08:57:52  step review succeeded — artifact 79866298: [reviewer] fix the login bug
  08:57:52  workflow finished: succeeded
```

The audit trail shows:
- **Run ID and Workflow**: Which workflow was executed and in which role
- **Invoker**: Identity asserted via --as (method: asserted, issuer: local)
- **Status**: Final outcome (succeeded/refused/error)
- **Ledger Integrity**: Cryptographic verification of event chain integrity
- **Artifact SHA**: First 8 hex chars of SHA256 hash; a fingerprint of what was computed
- **Step attribution**: Every agent step tied to the invoker and run ID

`audit` verifies the chain against itself; it can't tell a truncated tail
or a wholesale re-forged file from a genuine short run, since both are
internally consistent. If you recorded the head hash somewhere off the
machine beforehand, `audit verify --expect-head` catches exactly that:

```bash
./agenthof audit verify r-9e31cf9b --expect-head <hex>
```

A mismatch here means the run's tail was truncated or the file was
re-forged after the head was recorded; a match confirms the ledger you're
looking at is the one whose head you saved.

### 2.2 OIDC variant: use a password-grant token from Dex

This variant demonstrates identity assertion via OIDC, suitable for production (e.g., Okta, Auth0, or a local Dex instance).

First, ensure Dex is running. `docker compose` needs `LITELLM_MASTER_KEY` set even when only starting dex (the compose file interpolates it for the litellm service too); a placeholder is fine here:

```bash
export LITELLM_MASTER_KEY=anything
cd deploy
docker compose up -d dex
cd ..
```

Obtain an OIDC ID token via password grant (email: dana@example.com, password: demo1234):

```bash
TOKEN=$(curl -s -X POST http://localhost:5556/dex/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "username=dana@example.com" \
  -d "password=demo1234" \
  -d "client_id=agenthof" \
  -d "scope=openid email profile" | jq -r '.id_token')

echo "Token (first 50 chars): ${TOKEN:0:50}..."
```

The `email` scope is required: without it, dex's ID token carries only the
opaque `sub` claim (no `email`), and the audit trail below would show that
opaque subject instead of `dana@example.com`.

Set OIDC environment variables:

```bash
export AGENTHOF_OIDC_ISSUER=http://localhost:5556/dex
export AGENTHOF_OIDC_CLIENT_ID=agenthof
```

Run the workflow with the OIDC token:

```bash
./agenthof run software-engineer fix-bug \
  --input "fix the login bug" \
  --token "$TOKEN" \
  --executor echo \
  --config examples/config
```

Expected output:
```
workspace: .agenthof/workspaces/<unix-nano>
run r-<run-id> finished: succeeded
```

Audit the same run:

```bash
./agenthof audit r-<run-id>
```

Expected audit output (OIDC variant):
```
run r-<run-id> — fix-bug (role software-engineer)
invoked by dana@example.com (oidc, issuer http://localhost:5556/dex)
status: succeeded
ledger integrity: verified (8 events)
...
```

Note the identity method: when using an OIDC token, the invoker's identity is cryptographically verified against the issuer's signature; the token is bound to the run.

---

## Part 3: GOVERNANCE Moment — Role-Based Access Control & Budgeting

Demonstrates how roles enforce group membership (RBAC) and spending limits (budget).

### 3.1 Run with role-based access control

The accountant role restricts access to the finance group:

```yaml
# examples/config/roles/accountant.yaml
name: accountant
workflows: [reconcile-lite]
allowed_groups: [finance]
budget_usd_month: 20
```

Allow the run (invoker is in the finance group):

```bash
./agenthof run accountant reconcile-lite \
  --input "reconcile Q3 expenses" \
  --as finance-lead@example.com \
  --groups finance \
  --executor echo \
  --config examples/config
```

Expected output:
```
workspace: .agenthof/workspaces/<unix-nano>
run r-<run-id> finished: succeeded
```

### 3.2 Refuse the run (group mismatch) and ledger it

Attempt to run the same workflow as an invoker not in the finance group:

```bash
./agenthof run accountant reconcile-lite \
  --input "reconcile Q3 expenses" \
  --as engineer@example.com \
  --groups engineering \
  --executor echo \
  --config examples/config
```

Expected output:
```
workspace: .agenthof/workspaces/<unix-nano>
run r-ac91cc6a refused: role "accountant" requires membership in one of its allowed groups (finance); the invoker's groups don't qualify
```

Audit the refused run:

```bash
./agenthof audit r-ac91cc6a
```

Expected audit output:
```
run r-ac91cc6a — reconcile-lite (role accountant)
invoked by engineer@example.com (asserted, issuer local)
status: refused
ledger integrity: verified (1 events)

  08:58:04  run refused — role "accountant" requires membership in one of its allowed groups (finance); the invoker's groups don't qualify
```

Even though the run was refused, it is **ledgered** (recorded) in the audit trail for compliance. The refusal is chained into the run's ledger like every other event.

### 3.3 Budget enforcement via LiteLLM gateway

The accountant role has a monthly budget of $20. When the role's budget is exhausted, the model gateway returns HTTP 429 (Too Many Requests) and the step fails.

Provision the role key for billing:

```bash
export LITELLM_MASTER_KEY="your-secret-key"
cd deploy
docker compose up -d litellm
cd ..
./agenthof gateway provision --config examples/config
```

Expected output:
```
provisioned key for role software-engineer (budget $50)
provisioned key for role accountant (budget $20)
```

Run the workflow with the adk executor (model-backed):

```bash
./agenthof run accountant reconcile-lite \
  --input "reconcile Q3 expenses" \
  --as finance-lead@example.com \
  --groups finance \
  --executor adk \
  --config examples/config
```

If the role's monthly budget has been exhausted, LiteLLM rejects the request with HTTP 429. That is a step failure, not a refusal: the workflow's fail-back graph handles it, and the whole chain — including the failure — stays in the ledger.

For details on provisioning and budget behavior, see [`scripts/live-smoke.md`](../scripts/live-smoke.md).

---

## Part 4: INVESTIGATE Moment — Incident Investigation

Ties the other three together: when something goes wrong, `agenthof investigate`
merges the control log and every run log into one time-ordered timeline — so you
can see who changed what and which run it affected, without cross-referencing
files by hand.

### 4.1 Reproduce a small incident

One identity pulls an agent's kill switch; another tries to run:

```bash
# run in a fresh working directory (or after `rm -rf .agenthof`) for the output shown
./agenthof apply --as dana@example.com --config examples/config
./agenthof run software-engineer fix-bug --input "fix the login bug" --as dana@example.com --executor echo --config examples/config
./agenthof registry disable coder --as ops@example.com --config examples/config
./agenthof run software-engineer fix-bug --input "urgent prod bug" --as dana@example.com --executor echo --config examples/config
```

The last run is refused:
```
run r-<id> refused: configuration invalid
```

### 4.2 Investigate the timeline

```bash
./agenthof investigate
```

Expected output (timestamps and run ids vary; the sequence is the point):
```
investigation timeline: 11 event(s) across 3 source(s)
source: run .agenthof/runs/r-<healthy>.jsonl integrity=verified count=8
source: run .agenthof/runs/r-<refused>.jsonl integrity=verified count=1
source: control .agenthof/control.jsonl integrity=verified count=2
<ts> control apply — dana@example.com (asserted) [outcome=success]
<ts> run workflow_started — dana@example.com (asserted)
<ts> run step_started — dana@example.com (asserted) [agent=planner]
<ts> run step_succeeded — dana@example.com (asserted) [agent=planner]
<ts> run step_started — dana@example.com (asserted) [agent=coder]
<ts> run step_succeeded — dana@example.com (asserted) [agent=coder]
<ts> run step_started — dana@example.com (asserted) [agent=reviewer]
<ts> run step_succeeded — dana@example.com (asserted) [agent=reviewer]
<ts> run workflow_finished — dana@example.com (asserted) [outcome=succeeded]
<ts> control disable — ops@example.com (asserted) [agent=coder outcome=success]
<ts> run run_refused — dana@example.com (asserted) [outcome=refused reason=configuration invalid: workflows/fix-bug.yaml: fix-bug: workflow "fix-bug" depends on agent "coder", which is disabled in the registry]
integrity: OK
```

The story reads top to bottom: dana applied the config and ran a workflow
cleanly; ops disabled `coder`; dana's next run refused because the workflow
depends on the disabled agent. Two identities, control plane and runs, one
timeline — and every source's integrity is stated.

### 4.3 Filter the timeline

Narrow by outcome, agent, invoker, run, config hash, or time window:

```bash
./agenthof investigate --outcome refused
./agenthof investigate --agent coder
./agenthof investigate --since 1h
```

`--outcome refused` returns just the refusal:
```
<ts> run run_refused — dana@example.com (asserted) [outcome=refused reason=... "coder", which is disabled in the registry]
integrity: OK
```

Outcome literals are source-specific: **run** events use `succeeded|failed|refused`;
**control** events use `success|refused|rejected|error`. A duration passed to
`--since`/`--until` (e.g. `1h`, `720h`) is relative to now; an RFC3339 timestamp
is absolute (`--since` inclusive, `--until` exclusive).

### 4.4 The stable JSON contract

```bash
./agenthof investigate --json
```

Emits the versioned `investigate/1` object — the set `query`, per-source
`sources`, the `events`, and an `integrity` block:
```jsonc
{
  "v": "investigate/1",
  "query": {},
  "sources": [
    { "path": ".agenthof/runs/r-<healthy>.jsonl", "kind": "run", "integrity": "verified", "count": 8 },
    { "path": ".agenthof/control.jsonl", "kind": "control", "integrity": "verified", "count": 2 }
  ],
  "events": [
    { "time": "…", "source": "control", "kind": "apply",
      "invoker": { "subject": "dana@example.com", "issuer": "local", "method": "asserted" },
      "outcome": "success", "seq": 1 }
  ],
  "integrity": { "ok": true, "issues": [] }
}
```

`integrity.ok` equals `(exit code == 0)`, and `--json` never changes the exit
code. Exit codes: `0` all clean · `1` any source torn/broken (or an I/O error on
a source that exists) · `3` tainted only (a repair is on record) · `2` usage.

### 4.5 The config-join: which apply authorized a run

`audit <run-id>` closes the loop back to the control plane:

```bash
./agenthof audit r-<healthy>
```

The last line names the `apply` that put the config the run executed under:
```
config sha256:<hex> — applied by dana@example.com (asserted) at <ts>
```

If the control log is missing or damaged, this degrades to `control ledger
unavailable` — and it never changes the run audit's own exit code. Integrity is
always shown, never assumed; as everywhere in Agenthof, the ledger is
tamper-evident, not tamper-proof — see
[`docs/control-plane-lifecycle.md`](control-plane-lifecycle.md) for the full life
of a control action.

---

## Summary

- **CONFIG**: Registry applies instantly; dependencies are validated; kill switches (disable/enable) are atomic.
- **AUDIT**: Every run is attributed to an invoker (asserted or OIDC-verified); artifacts are SHA256-hashed for integrity; refused runs are still ledgered.
- **GOVERNANCE**: Role-based access (allowed_groups) and role-based budgeting (via LiteLLM) control who can run what and at what cost.
- **INVESTIGATE**: One time-ordered timeline across the control plane and every run — filterable, with a stable `investigate/1` JSON contract, per-source integrity, and a config-join from each run back to the apply that authorized it.
