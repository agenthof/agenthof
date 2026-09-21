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
  `contained` / `fronted` execution tiers;
- a control-plane audit — every `apply` and kill-switch flip is recorded to
  its own hash-chained control ledger, attributed to the human who invoked
  it, with `audit control`, `audit verify control`, and `audit repair
  control`;
- incident investigation — `agenthof investigate` merges the control log and
  every run log into one filterable, time-ordered timeline (human or `--json`),
  and `audit <run-id>` names the exact `apply` that put a run's config on record.

What's shipped versus what's coming — a tool/MCP gateway, governed skills,
multi-resource scope — is laid out in the [roadmap](ROADMAP.md). Only shipped
items are guarantees.

## Quickstart

**Requires:** Go >= 1.27 toolchain; Linux or macOS.

    go build -o agenthof ./cmd/agenthof
    ./agenthof apply --as you@example.com --config examples/config
    ./agenthof run software-engineer fix-bug --input "fix the login bug" --as you@example.com --config examples/config
    ./agenthof audit <run-id>

Expected output from `apply`:

    registry ok: 5 agents, 2 workflows, 2 roles
    control head: seq=1 sha256=<hex>

The `control head` line is the control ledger recording the apply, attributed
to `--as` (or your OS user if omitted); the hash varies per run. See
[`ROADMAP.md`](ROADMAP.md) and `audit control` for the control-plane audit.

See [`docs/quickstart.md`](docs/quickstart.md) for the kill switch, model-backed runs (LiteLLM), retention, and the full walkthrough.

## The idea in three commands

```
agenthof apply ./config      # roles, workflows, agents — validated, governed
agenthof run software-engineer fix-bug --input "..."
agenthof audit <run-id>      # who asked → what ran → what it touched → what it cost
```

## Investigate an incident

```
agenthof investigate --since 24h --agent coder --outcome refused
agenthof investigate --json | jq          # the stable investigate/1 contract
```

One filterable, time-ordered timeline across the control plane and every run —
who changed what, which `apply` authorized each run's config, and whether the
record can be trusted. Integrity is always shown, never assumed. See
[`docs/reference/config.md`](docs/reference/config.md) for the flags, exit codes,
and the `investigate/1` JSON contract.

## The three demos

Walk through CONFIG (registry management), AUDIT (run traceability), and GOVERNANCE (RBAC + budgeting) with scripted end-to-end examples.

See [`docs/demo.md`](docs/demo.md) for the full walkthrough.

## Documentation

- [`ROADMAP.md`](ROADMAP.md) — what's shipped, next, later, and exploratory.
- [`docs/quickstart.md`](docs/quickstart.md) — build, run, kill switch,
  model-backed runs, retention.
- [`docs/concepts.md`](docs/concepts.md) — the ideas behind the registry:
  planes, gateways, execution tiers, identity, the ledger.
- [`docs/lifecycle.md`](docs/lifecycle.md) — the life of a run: how one
  invocation flows through identity, authorization, execution, and the ledger.
- [`docs/control-plane-lifecycle.md`](docs/control-plane-lifecycle.md) — the
  life of a control action: apply, the kill switch, and the control ledger.
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

How the project is maintained — and why trust rests on the license, the
constitution, and the DCO rather than on any identity — is in
[GOVERNANCE.md](GOVERNANCE.md).

Contributions are welcome under the DCO — see [CONTRIBUTING.md](CONTRIBUTING.md).
Security reports: see [SECURITY.md](SECURITY.md).
