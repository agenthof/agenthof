# Live smoke: a fronted agent

Start the reference agent, apply the example config, run a workflow, and
read the ledger. This is the path a run actually takes.

## Start the agent

From the repository root:

```bash
go run ./examples/echo-agent
```

It listens on `127.0.0.1:8080`. The example agents' `endpoint` values are
`http://127.0.0.1:8080/`. Leave this process running. It echoes each step's
input back as the artifact and holds no credentials.

If that port is taken, start it elsewhere and point the agents at it:

```bash
go run ./examples/echo-agent -addr 127.0.0.1:18080
```

Then set every `endpoint` under `examples/config/agents/` to
`http://127.0.0.1:18080/`.

## Apply and run

In another terminal, from the repository root:

```bash
go build -o agenthof ./cmd/agenthof
./agenthof apply --as you@example.com --config examples/config
./agenthof run software-engineer fix-bug \
  --input "fix the login bug" \
  --as you@example.com \
  --config examples/config
```

Expected `apply`:

```
registry ok: 5 agents, 2 workflows, 2 roles
control head: seq=1 sha256=<hex>
```

Expected `run`:

```
run r-<run-id> finished: succeeded
```

If the echo agent is not listening, the run finishes `failed`. The ledger
records the connection error as a step failure.

## Audit

```bash
./agenthof audit <run-id>
```

Expected:

- the invoker, role, and workflow
- eight events: workflow started, three steps started and succeeded, workflow finished
- each successful step's artifact preview `fix the login bug` and SHA-256 prefix `f7459994` (the echo of the input)
- `ledger integrity: verified (8 events)`

## What this does not exercise

The echo agent does not call the model door. That door is live for an agent
that posts to `<proxy URL>v1/chat/completions` with the run token — see
`examples/model-agent` and [`docs/lifecycle-model.md`](../docs/lifecycle-model.md).
Tool and exec doors are live when an agent declares them; the example
agents declare neither. The listener and its two headers are still sent on
every fronted step.
