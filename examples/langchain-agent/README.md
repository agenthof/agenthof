# langchain-agent

A [LangChain](https://python.langchain.com/) agent that runs governed under
Agenthof. It serves the [agent protocol](../../docs/agent-protocol.md) and
answers each step with **one model call made through Agenthof's gateway** — it
holds no provider key and never talks to a provider directly.

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
library plus `langchain-openai`, which brings `httpx`).

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python agent.py --addr 127.0.0.1:8082           # TCP, for local development
.venv/bin/python agent.py -socket /path/to/agent.sock     # Unix socket (note the single dash)
```

Point an agent definition at it (`endpoint: http://127.0.0.1:8082/` or
`endpoint: unix:///path/to/agent.sock`) with `model: fast`, and the gateway's
`fast` route at your provider. `--model` changes the logical name the agent
sends; it must match the agent's configured `model`.

`scripts/e2e-langchain-local.sh` runs the whole thing against a real `agenthof`
over Unix sockets with a stand-in provider, and `deploy/refbox/Containerfile.python`
builds it into a no-network compartment.

## Behaviour on the step endpoint

| Request | Reply |
|---|---|
| valid step with both gateway headers | `200 {"artifact": <model reply>, "success": true}` |
| gateway headers missing | `200 {"success": false, "reason": "model proxy coordinates missing"}` |
| the model call fails for any reason (refused model, unreachable gateway, upstream error) | `200 {"success": false, "reason": "model call failed"}` — the reason is fixed so no URL, token, or upstream text reaches the ledger |
| body not JSON, not an object, `input` not a string, bad `Content-Length` | `400` |
| body over 1 MiB | `413` |

## A caution for TCP development

Over TCP the run token is the OpenAI client's `api_key`. LangChain tracing
(LangSmith) would log it if enabled; leave tracing off while pointing this agent
at a gateway. Inside the compartment this cannot arise: there is no network and
no tracing environment.
