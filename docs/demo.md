# The Three Demos

This document walks through three scripted demonstrations of Agenthof's core governance capabilities:
CONFIG (agent registry management), AUDIT (run traceability and integrity), and GOVERNANCE (role-based access control and budgeting).

## Part 1: CONFIG Moment — Registry Management & Kill Switches

Demonstrates how roles, workflows, and agents are defined in YAML and validated on apply; and how the kill switch prevents invalid configurations from running.

### 1.1 Apply and verify the registry

```bash
cd <path-to-your-clone>
./agenthof apply --config examples/config
```

Expected output:
```
registry ok: 5 agents, 2 workflows, 2 roles
```

The registry now includes:
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
./agenthof apply --config examples/config
```

Expected output:
```
registry ok: 5 agents, 2 workflows, 2 roles
```

Configuration changes are validated immediately; no stale configs can propagate.

### 1.3 Test the kill switch: disable an agent and watch apply fail

Disable the coder agent:

```bash
./agenthof registry disable coder --config examples/config
```

Expected output:
```
agent coder disabled
```

Now try to apply:

```bash
./agenthof apply --config examples/config
```

Expected output:
```
workflows/fix-bug.yaml: fix-bug: workflow "fix-bug" depends on agent "coder", which is disabled in the registry
```

The registry refuses to load because fix-bug depends on coder, which is now disabled. The error names the broken workflow immediately.

Re-enable the agent:

```bash
./agenthof registry enable coder --config examples/config
```

Expected output:
```
agent coder enabled
```

Verify the registry is healthy again:

```bash
./agenthof apply --config examples/config
```

Expected output:
```
registry ok: 5 agents, 2 workflows, 2 roles
```

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

## Summary

- **CONFIG**: Registry applies instantly; dependencies are validated; kill switches (disable/enable) are atomic.
- **AUDIT**: Every run is attributed to an invoker (asserted or OIDC-verified); artifacts are SHA256-hashed for integrity; refused runs are still ledgered.
- **GOVERNANCE**: Role-based access (allowed_groups) and role-based budgeting (via LiteLLM) control who can run what and at what cost.
