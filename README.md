# Agenthof

**The open-source agent registry: every agent in your org gets an identity,
a privilege set, a kill switch, and a ledger of who ran it.**

Define your AI workforce as roles in YAML — a role owns workflows, a workflow
composes agents, and every action any agent takes is contained by construction
and attributed to the human who asked for it.

> *Agenthof* — from the German **Hof**: the court. Where your agents are
> housed, and what they answer to.

## Status

Pre-release. The V1 design is complete; implementation is underway.

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
