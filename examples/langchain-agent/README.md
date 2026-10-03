# langchain-agent

A [LangChain](https://python.langchain.com/) agent that runs governed under
Agenthof. It serves the [agent protocol](../../docs/agent-protocol.md) and
reaches models, commands, tools, and sub-agents **only through Agenthof's
per-run gateway** — it holds no provider key, no tool credential, and no
command authority of its own. Two drivers decide how a step is answered:

- `--driver model` (the default) — one model call through the gateway; the
  reply is the step artifact.
- `--driver scripted` — every door, in a fixed order: one model call, one
  first-hand command through the exec door, one call on an on-behalf-of tool
  resource and one on a bridged stdio resource through the tool door, then
  parallel sub-agent runs through the spawn door. The artifact reports each
  leg (`model:`, `exec:`, `tool <name>:` lines, and one `spawn:` line per
  child), so an audit can be checked against it; the command output, tool
  results, and child previews are each collapsed onto their one line.
  `--exec-argv` (space-separated), `--obo-tool`, `--bridge-tool`,
  `--spawn-role`, `--spawn-workflow` and `--spawns` (at least 1) name what it
  calls; the defaults (`env`, `whoami`, `echo`, `acceptance-worker`,
  `acceptance-sub`, `2`) match `scripts/e2e-acceptance-local.sh`.
- `--driver llm` is reserved (a model choosing the doors) and exits 2 today.

The tool door is spoken with the official `mcp` Python SDK (pinned to its 1.x
line in `requirements.txt`); the exec and spawn doors are plain JSON over the
same gateway URL. Over `unix://` every client dials the socket.

How the call is governed: Agenthof passes two headers on every step,
`X-Agenthof-Proxy-URL` and `X-Agenthof-Run-Token`. The agent points
`ChatOpenAI` at `<proxy-url>/v1` with the run token as its API key and the
**logical** model name it is configured with (`fast` by default). Agenthof
authorizes that name, injects the real provider key upstream, forwards the call,
and records a `model_call` on the run's ledger. Any other model name is refused
with `403`.

Two proxy-URL forms are handled:

- `http://127.0.0.1:<port>/` — the default gateway. The trailing slash is
  stripped before `/v1` is appended, so the request hits `/v1/chat/completions`
  directly instead of bouncing through a redirect.
- `unix://<socket-path>` — what Agenthof emits when `gateway.refbox_socket_dir`
  is set, as inside the [refbox](../../deploy/refbox) compartment. The agent
  dials the socket with an httpx Unix-socket transport; the URL's host is a
  placeholder.

The agent is pinned to the chat-completions route (`use_responses_api=False`):
the gateway serves only `/v1/chat/completions`.

## Run it

Dependencies: Python 3.10+ and the pinned `requirements.txt` (the standard
library plus `langchain-openai`, which brings `httpx`, and `mcp`).

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python agent.py --addr 127.0.0.1:8082           # TCP, for local development
.venv/bin/python agent.py -socket /path/to/agent.sock     # Unix socket (note the single dash)
.venv/bin/python agent.py -socket /path/to/agent.sock -workspace /ignored  # a compartment supervisor appends -workspace; it is accepted and ignored
.venv/bin/python agent.py -socket /path/to/agent.sock --driver scripted     # every door in one step
```

Point an agent definition at it (`endpoint: http://127.0.0.1:8082/` or
`endpoint: unix:///path/to/agent.sock`) with `model: fast`, and the gateway's
`fast` route at your provider. `--model` changes the logical name the agent
sends; it must match the agent's configured `model`.

`scripts/e2e-langchain-local.sh` runs the model driver against a real
`agenthof` over Unix sockets with a stand-in provider;
`scripts/e2e-acceptance-local.sh` runs the scripted driver through every door
in one governed run and checks the whole audit timeline, hermetically (it
proves governance and audit, not containment — the compartments there are
host processes). `deploy/refbox/Containerfile.python` builds the agent into a
no-network compartment.

## Behaviour on the step endpoint

| Request | Reply |
|---|---|
| valid step with both gateway headers | `200 {"artifact": <model reply>, "success": true}` |
| gateway headers missing | `200 {"success": false, "reason": "model proxy coordinates missing"}` |
| the model call fails for any reason (refused model, unreachable gateway, upstream error) | `200 {"success": false, "reason": "model call failed"}` — the reason is fixed so no URL, token, or upstream text reaches the ledger |
| `--driver scripted`: every leg succeeds | `200 {"artifact": <the per-leg report>, "success": true}` |
| `--driver scripted`: a leg fails or a door refuses (an off-allowlist command, a spawn target not on `may_spawn`, an upstream error) | `200 {"success": false, "reason": "<leg> call failed"}` — one of `model call failed`, `exec call failed`, `tool call failed`, `spawn call failed`; nothing after the failed leg runs, and the reason is fixed so no URL, token, or upstream text reaches the ledger |
| body not JSON, not an object, `input` not a string, bad `Content-Length` | `400` |
| body over 1 MiB | `413` |

## A caution for TCP development

Over TCP the run token is the OpenAI client's `api_key`. LangChain tracing
(LangSmith) would log it if enabled; leave tracing off while pointing this agent
at a gateway. Inside the compartment this cannot arise: there is no network and
no tracing environment.
