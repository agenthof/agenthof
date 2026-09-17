# Agenthof

**The open-source agent registry: every agent in your org gets an identity,
a privilege set, a kill switch, and a ledger of who ran it.**

Define your AI workforce as roles in YAML — a role owns workflows, a workflow
composes agents, and every action any agent takes is contained by construction
and attributed to the human who asked for it.

> *Agenthof* — from the German **Hof**: the court. Where your agents are
> housed, and what they answer to.

## Status

Pre-release. The core is real: config → validated registry → event-sourced
engine (linear + fail-back) → invoker-attributed audit trail, running offline
with a built-in echo executor. Model-backed agents (ADK), gateways, OIDC, and
RBAC land next.

## Quickstart

    go build -o agenthof ./cmd/agenthof
    ./agenthof apply --config examples/config
    ./agenthof run software-engineer fix-bug --input "fix the login bug" --as you@example.com --config examples/config
    ./agenthof audit <run-id>

Try the kill switch:

    ./agenthof registry disable coder --config examples/config
    ./agenthof apply --config examples/config   # fails, naming every dependent workflow

### Model-backed runs (LiteLLM)

To run agents with real models instead of the echo executor, use a local LiteLLM gateway:

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
**Requires:** Go >= 1.26.6 toolchain (auto-downloaded via `go.mod`).

For the full end-to-end walkthrough, including budget behavior and audit trails, see [`scripts/live-smoke.md`](scripts/live-smoke.md).

Retention (compliance floor, free forever):

    ./agenthof runs prune --older-than 180d

## The idea in three commands

```
agenthof apply ./config      # roles, workflows, agents — validated, governed
agenthof run software-engineer fix-bug --input "..."
agenthof audit <run-id>      # who asked → what ran → what it touched → what it cost
```

## License

Apache-2.0

## Governance

- [`docs/constitution.md`](docs/constitution.md) — the binding invariants every change must honor.
- [`docs/design/v1-design.md`](docs/design/v1-design.md) — the committed V1 design spec.
- [`docs/development.md`](docs/development.md) — how this repo is built, reviewed, and merged.
