# Quickstart

## Build and run with the echo executor

    go build -o agenthof ./cmd/agenthof
    ./agenthof apply --config examples/config
    ./agenthof run software-engineer fix-bug --input "fix the login bug" --as you@example.com --config examples/config
    ./agenthof audit <run-id>

Expected output from `apply`:

    registry ok: 5 agents, 2 workflows, 2 roles

`run` prints the run id it assigned (`run <run-id> finished: ...`); pass that
id to `audit` to see the trace rendered from the run's event log — who
invoked the run, the role and workflow, status, ledger integrity, and each
step with its agent and outcome (see
[`docs/concepts.md`](concepts.md#the-ledger) for what the ledger records and
[`docs/demo.md`](demo.md) for a full walkthrough of the AUDIT and GOVERNANCE
demos, including budget refusals).

Try the kill switch:

    ./agenthof registry disable coder --config examples/config
    ./agenthof apply --config examples/config   # fails, naming every dependent workflow

Retention (compliance floor, free forever):

    ./agenthof runs prune --older-than 180d

## Model-backed runs (LiteLLM)

To run agents with real models instead of the echo executor, use a local LiteLLM gateway.
`docker compose` requires `LITELLM_MASTER_KEY` to be set before you start it
(`deploy/docker-compose.yml` reads it from the environment), and
`agenthof gateway provision` requires the same variable:

    export LITELLM_MASTER_KEY="any-secret-key"
    cd deploy
    docker compose up -d                                    # start LiteLLM
    cd ..
    ./agenthof gateway provision --config examples/config   # provision per-role keys
    ./agenthof run software-engineer fix-bug \
      --executor adk \
      --input "your task here" \
      --as you@example.com \
      --config examples/config

`run` auto-loads the role key from `.agenthof/keys/<role>.key` (`gateway.LoadRoleKey`), so no
export is needed once a role has been provisioned. Setting `AGENTHOF_GATEWAY_KEY` yourself is
OPTIONAL — a fallback used only when no role key file exists yet.

**Important:** Role keys live under `.agenthof/keys/` and are gitignored; never commit them.
**Requires:** Go >= 1.27 toolchain (auto-downloaded via `go.mod`).

For the full end-to-end walkthrough, including budget behavior and audit trails, see [`scripts/live-smoke.md`](../scripts/live-smoke.md).

## Next

- [`docs/concepts.md`](concepts.md) — the ideas behind the registry, the
  execution tiers, identity, and the ledger.
- [`docs/reference/config.md`](reference/config.md) — every YAML field.
- [`docs/demo.md`](demo.md) — the three scripted demos (CONFIG, AUDIT,
  GOVERNANCE).
