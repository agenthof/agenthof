# Agenthof

**The open-source agent registry: every agent in your org gets an identity,
a privilege set, a kill switch, and a ledger of who ran it.**

Define your AI workforce as roles in YAML — a role owns workflows, a workflow
composes agents, and every action any agent takes is contained by construction
and attributed to the human who asked for it.

> *Agenthof* — from the German **Hof**: the court. Where your agents are
> housed, and what they answer to.

## Status

Pre-release, and the governed core is real and runnable today:

- config → validated registry → event-sourced engine (linear + fail-back),
  runnable offline with a built-in echo executor;
- a hash-chained ledger where every action and refusal is attributed to the
  human who invoked it, with `audit verify` for integrity;
- the kill switch, OIDC + RBAC, per-role model-gateway keys and budgets, and
  `contained` / `fronted` execution tiers.

What's shipped versus what's coming — control-plane audit, a tool/MCP gateway,
governed skills, multi-resource scope — is laid out in the
[roadmap](ROADMAP.md). Only shipped items are guarantees.

## Quickstart

**Requires:** Go >= 1.27 toolchain; Linux or macOS.

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

- [`ROADMAP.md`](ROADMAP.md) — what's shipped, next, later, and exploratory.
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

Every change is held to the invariants in
[`docs/constitution.md`](docs/constitution.md): containment, identity, the
ledger, compliance floors, the license, and scope discipline. They change
only by an explicit commit that amends that file.

Contributions are welcome under the DCO — see [CONTRIBUTING.md](CONTRIBUTING.md).
Security reports: see [SECURITY.md](SECURITY.md).
