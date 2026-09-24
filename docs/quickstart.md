# Quickstart

## Build, start the example agent, and run

Agents are external HTTP services. The example config points every agent at
`http://127.0.0.1:8080/`, which is where `examples/echo-agent` listens. Start
it first, in its own terminal, and leave it running:

    go run ./examples/echo-agent

It holds no credentials. Each step's input comes back as the artifact.

If port 8080 is already taken, start it on another loopback port and set
every example agent's `endpoint` to match:

    go run ./examples/echo-agent -addr 127.0.0.1:18080

Then, from the repository root:

    go build -o agenthof ./cmd/agenthof
    ./agenthof apply --as you@example.com --config examples/config
    ./agenthof run software-engineer fix-bug --input "fix the login bug" --as you@example.com --config examples/config
    ./agenthof audit <run-id>

Expected output from `apply`:

    registry ok: 5 agents, 2 workflows, 2 roles
    control head: seq=1 sha256=<hex>

The `control head` line is the control ledger recording the apply (see the
control-plane audit below); the `seq` advances with each control action and
the hash varies.

`run` prints the run id it assigned (`run <run-id> finished: succeeded`).
Pass that id to `audit`. With the echo agent, each of the three steps
records the same artifact — the input, echoed back:

    ledger integrity: verified (8 events)
      ...
      step plan succeeded — artifact f7459994: fix the login bug
      step code succeeded — artifact f7459994: fix the login bug
      step review succeeded — artifact f7459994: fix the login bug

If the echo agent is not listening, the run finishes `failed` and the ledger
records the connection error. That is a step failure, not a refusal.

See [`docs/concepts.md`](concepts.md#the-ledger) for what the ledger records
and [`docs/demo.md`](demo.md) for the AUDIT and GOVERNANCE walkthroughs.

Try the kill switch:

    ./agenthof registry disable coder --as you@example.com --config examples/config
    ./agenthof apply --as you@example.com --config examples/config   # fails, naming every dependent workflow

The disable is itself recorded in the control ledger, attributed to `--as`.
See who flipped the kill switch and when:

    ./agenthof audit control

Retention (compliance floor, free forever) — leaves the control ledger and its
repair fragments untouched:

    ./agenthof runs prune --older-than 180d

Model calls go through Agenthof when the agent targets the per-run proxy
URL. `examples/echo-agent` does not make them. `examples/model-agent` does,
and it needs an OpenAI-compatible endpoint in `gateway.models`.
`gateway provision` writes a per-role key the model door injects;
`budget_usd_month` is enforced by that upstream gateway, not by Agenthof.
See [`docs/lifecycle-model.md`](lifecycle-model.md).

**Requires:** Go >= 1.27 toolchain (auto-downloaded via `go.mod`).

## Next

- [`docs/concepts.md`](concepts.md) — the ideas behind the registry, the
  doors, identity, and the ledger.
- [`docs/reference/config.md`](reference/config.md) — every YAML field.
- [`docs/demo.md`](demo.md) — the scripted demos (CONFIG, AUDIT, GOVERNANCE,
  INVESTIGATE).
