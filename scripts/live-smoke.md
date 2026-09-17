# Live Smoke Test: Model-Backed Runs with LiteLLM

This script demonstrates end-to-end model-backed execution via a local LiteLLM gateway.

## Setup

Export your Anthropic credentials and LiteLLM master key:

```bash
export ANTHROPIC_API_KEY="your-anthropic-key"
export LITELLM_MASTER_KEY="any-secret-key"
```

Start the gateway (from the repo root):

```bash
docker compose -f deploy/docker-compose.yml up -d
```

Provision the example roles and obtain gateway keys:

```bash
./agenthof gateway provision --config examples/config
```

This creates role keys in `.agenthof/keys/` (gitignored, never commit).

## Verification

Before running the agent, verify the LiteLLM Responses API is available:

```bash
curl -s http://localhost:4000/responses \
  -H "Authorization: Bearer $(cat .agenthof/keys/software-engineer.key)" \
  -H 'Content-Type: application/json' \
  -d '{"model":"fast","input":"ping"}' | head -c 400
```

If this returns 404, the LiteLLM version does not support the Responses API and must be updated.

## Run

Invoke the agent:

```bash
./agenthof run software-engineer fix-bug \
  --executor adk \
  --input "write NOTES.md summarizing this task" \
  --as you@example.com \
  --config examples/config
```

`run` auto-loads the role key from `.agenthof/keys/<role>.key` (`gateway.LoadRoleKey`), so no
`export` is needed once a role has been provisioned. Exporting `AGENTHOF_GATEWAY_KEY` yourself
is OPTIONAL / fallback-only — it's only consulted when no role key file exists yet.

This runs a complete workflow:
1. The agent plans the task
2. Executes the plan via ADK (model-backed actions)
3. Stops when budget is exhausted (monthly budget: $50)

## Audit

Inspect the run:

```bash
./agenthof audit <run-id>
```

Expected output includes:
- All actions taken by the agent
- Model costs accumulated per step
- Budget remaining or exhausted state
- If budget exhausted mid-task: a note that re-running will skip already-completed steps and resume from the checkpoint

## Notes

- The admin key-check (`gateway provision`'s `GET /key/info?key=...`) passes
  the key as a query parameter, so it may appear in LiteLLM server access
  logs — run the gateway on localhost or behind TLS.
