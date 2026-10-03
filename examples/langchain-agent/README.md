# langchain-agent

A [LangChain](https://python.langchain.com/) agent that runs governed under
Agenthof. It serves the [agent protocol](../../docs/agent-protocol.md) and
reaches models, commands, tools, and sub-agents **only through Agenthof's
per-run gateway** — it holds no provider key, no tool credential, and no
command authority of its own. Three drivers decide how a step is answered:

- `--driver model` (the default) — one model call through the gateway; the
  reply is the step artifact.
- `--driver scripted` — every door, in a fixed order: one model call, one
  first-hand command through the exec door, one call on an on-behalf-of tool
  resource and one on a bridged stdio resource through the tool door, then
  parallel sub-agent runs through the spawn door. The artifact reports each
  leg (`model:`, `exec:`, `tool <name>:` lines, and one `spawn:` line per
  child), so an audit can be checked against it; the model reply, command
  output, tool results, and child previews are each collapsed onto their one
  line.
  `--exec-argv` (space-separated), `--obo-tool`, `--bridge-tool`,
  `--spawn-role`, `--spawn-workflow` and `--spawns` (at least 1) name what it
  calls; the defaults (`env`, `whoami`, `echo`, `acceptance-worker`,
  `acceptance-sub`, `2`) match `scripts/e2e-acceptance-local.sh`.
- `--driver llm` — a model chooses. The agent discovers the tools its grant
  actually mirrors on the tool door, offers them to the model together with
  two door tools, `exec(command)` and `spawn(role, workflow, input)`, and
  runs the model's tool calls round by round — each round's calls
  concurrently (at most 8 at once), so two `spawn` calls made in one turn run
  in parallel — until the model answers without calling a tool. What the
  model is fed back when a door does not return a result is one of four fixed
  texts: a door that refuses a call (`403`) is `refused by policy`; any other
  door error is `the door call failed`; a tool the model made up is
  `unknown tool`; ill-formed arguments are `invalid arguments` (no door is
  dialed). `invalid arguments` covers the shape checks on the two door tools
  and any call whose arguments were not a JSON object; the arguments of a
  discovered tool are passed through as given, and an upstream error on one
  is `the door call failed`. Each result fed back is cut at 8 KiB. The step
  fails, with a fixed reason, when `--max-rounds` (default 8) or
  `--step-budget` seconds (default 240; set it below the engine's
  `step_timeout`) is spent, or when the conversation would outgrow the model
  door's request limit. The `scripted` flags name what the prompt asks the
  model to do. The artifact has one line per leg the model actually took
  (`model: called …`/`model: <answer>`, `exec:`, `tool <name>:`, `spawn:`).
  It is the agent's own summary, asserted by the agent; the door events on
  the run's ledger are the first-hand record of what was called. A real
  model may take a different path from run to run, so the artifact of one
  step is not a prediction of the next.

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
.venv/bin/python agent.py -socket /path/to/agent.sock -workspace /ignored  # the hermetic refspawn test stand-in appends -workspace (the shipped supervisor mounts the volume at /work instead); accepted and ignored
.venv/bin/python agent.py -socket /path/to/agent.sock --driver scripted     # every door in one step
.venv/bin/python agent.py -socket /path/to/agent.sock --driver llm --max-rounds 8 --step-budget 150  # a model chooses the doors
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
host processes). `scripts/e2e-acceptance-llm-local.sh` runs the llm driver
through the same harness, hermetically, with a tool-calling stand-in for the
provider that plays a fixed script — governance and audit of the loop, not
containment, and the stand-in is not a real model.
`deploy/refbox/Containerfile.python` builds the agent into a no-network
compartment.

## Behaviour on the step endpoint

| Request | Reply |
|---|---|
| valid step with both gateway headers | `200 {"artifact": <model reply>, "success": true}` |
| gateway headers missing | `200 {"success": false, "reason": "model proxy coordinates missing"}` |
| the model call fails for any reason (refused model, unreachable gateway, upstream error) | `200 {"success": false, "reason": "model call failed"}` — the reason is fixed so no URL, token, or upstream text reaches the ledger |
| `--driver scripted`: every leg succeeds | `200 {"artifact": <the per-leg report>, "success": true}` |
| `--driver scripted`: a leg fails or a door refuses (an off-allowlist command, a spawn target not on `may_spawn`, an upstream error) | `200 {"success": false, "reason": "<leg> call failed"}` — one of `model call failed`, `exec call failed`, `tool call failed`, `spawn call failed`; nothing after the failed leg runs, and the reason is fixed so no URL, token, or upstream text reaches the ledger |
| `--driver llm`: the model answers without a tool call | `200 {"artifact": <one line per leg>, "success": true}` — a door's refusal along the way is a `refused by policy` line, not a failed step |
| `--driver llm`: the model never stops, the step budget runs out, the tool door's listing fails, a granted tool is named `exec` or `spawn`, the conversation would exceed the door's limit, or a model call fails | `200 {"success": false, "reason": "<fixed>"}` — one of `round cap reached`, `step deadline reached`, `tool call failed`, `tool set conflict`, `conversation too large`, `model call failed` |
| body not JSON, not an object, `input` not a string, bad `Content-Length` | `400` |
| body over 1 MiB | `413` |

## A caution for TCP development

Over TCP the run token is the OpenAI client's `api_key`. LangChain tracing
(LangSmith) would log it if enabled; leave tracing off while pointing this agent
at a gateway. Inside the compartment this cannot arise: there is no network and
no tracing environment.
