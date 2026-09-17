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
RBAC are implemented.

## Quickstart

    go build -o agenthof ./cmd/agenthof
    ./agenthof apply --config examples/config
    ./agenthof run software-engineer fix-bug --input "fix the login bug" --as you@example.com --config examples/config
    ./agenthof audit <run-id>

Expected output from `apply`:

    registry ok: 5 agents, 2 workflows, 2 roles

See [`docs/quickstart.md`](docs/quickstart.md) for the kill switch, model-backed runs (LiteLLM), retention, and the full walkthrough.

## The idea in three commands

```
agenthof apply ./config      # roles, workflows, agents — validated, governed
agenthof run software-engineer fix-bug --input "..."
agenthof audit <run-id>      # who asked → what ran → what it touched → what it cost
```

## The three demos

Walk through CONFIG (registry management), AUDIT (run traceability), and GOVERNANCE (RBAC + budgeting) with scripted end-to-end examples.

See [`docs/demo.md`](docs/demo.md) for the full walkthrough.

## Documentation

- [`docs/quickstart.md`](docs/quickstart.md) — build, run, kill switch,
  model-backed runs, retention.
- [`docs/concepts.md`](docs/concepts.md) — the ideas behind the registry:
  planes, gateways, execution tiers, identity, the ledger.
- [`docs/reference/config.md`](docs/reference/config.md) — every YAML field,
  required/optional, defaults, and validation rules.
- [`docs/demo.md`](docs/demo.md) — the three scripted demos (CONFIG, AUDIT,
  GOVERNANCE).
- [`docs/constitution.md`](docs/constitution.md) — the binding invariants
  every change must honor.

## License

Apache-2.0

## Governance

- [`docs/constitution.md`](docs/constitution.md) — the binding invariants every change must honor.
- [`docs/design/v1-design.md`](docs/design/v1-design.md) — the committed V1 design spec.
- [`docs/development.md`](docs/development.md) — how this repo is built, reviewed, and merged.

Contributions are welcome under the DCO — see [CONTRIBUTING.md](CONTRIBUTING.md).
Security reports: see [SECURITY.md](SECURITY.md).
