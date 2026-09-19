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

This runs the workflow's steps against the real model through the gateway. If
the role's key has exhausted its budget, the gateway returns HTTP 429 and that
step fails; the workflow's fail-back graph handles it like any other step
failure, and the whole chain stays in the ledger.

## Audit

Inspect the run:

```bash
./agenthof audit <run-id>
```

Expected output includes:
- The invoker, role, and workflow for the run
- Every step event in order, with the agent that ran it and its execution tier
- The artifact SHA-256 prefix and preview for each successful step
- The integrity line: `ledger integrity: verified (N events)`

## Notes

- The admin key-check (`gateway provision`'s `GET /key/info?key=...`) passes
  the key as a query parameter, so it may appear in LiteLLM server access
  logs — run the gateway on localhost or behind TLS.
