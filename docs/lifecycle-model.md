# The life of a model call

One chat completion, from the moment a fronted agent asks until the ledger
line that records it. This is the model door. For the run it happens inside,
see [`lifecycle.md`](lifecycle.md). For the YAML, see
[`reference/config.md`](reference/config.md#models).

```
  agent                         Agenthof                         provider
    |  POST /v1/chat/completions    |                               |
    |  Authorization: Bearer        |                               |
    |    <run token>                |-- logical model allowed?      |
    |  {"model":"<logical>"}        |   no → 403, model_call refused|
    |                               |   yes                          |
    |                               |-- inject per-role provider key |
    |                               |   rewrite model to provider's  |
    |                               |   POST /v1/chat/completions --> |
    |                               |                    (never the run token)
    |                               | <-- completion (or 429) ------- |
    | <-- relayed response          |-- model_call -----------------> ledger
```

## When the door exists

Every fronted step starts a listener on `127.0.0.1` and an ephemeral port.
The call out to the agent carries `X-Agenthof-Proxy-URL` and
`X-Agenthof-Run-Token`. The agent points an OpenAI-compatible client at
`<proxy URL>v1` and sends the run token as the bearer. The same listener
serves tools and exec when the agent declares them. An agent that does not
call a model ignores the headers.

The listener is reachable only from the host Agenthof runs on. The run token
is never written to the ledger. When the step finishes, the listener shuts
down and the token stops working.

## Authorize, then inject

The agent sends the **logical** model name (`"model": "planner-model"`).
That is the only name it should know. Agenthof allows the call only when
that name equals the agent's effective model: `model` on the agent, or
`gateway.defaults.model` when the agent's `model` is empty. Anything else is
`403` and a `model_call` with status `refused`. The provider is not called.

On a match, Agenthof resolves the logical name to a route: a provider
endpoint, a provider model name, and a key.

- **Budgeted path.** `agenthof gateway provision` writes a per-role key at
  `.agenthof/keys/<role>.key` in the working directory, with
  `budget_usd_month` as that key's budget at the upstream gateway (LiteLLM).
  The model door reads that same directory. Injecting the key means the
  upstream gateway enforces the budget. An exhausted budget comes back as
  HTTP 429. Agenthof relays the 429 and records `model_call` status
  `refused`, reason `budget`. It does not copy the upstream error body into
  the ledger.
- **Unbudgeted path.** No role key file → the route's `api_key_env`. No
  budget. This is the dev path.

Agenthof does not itself cap spend. The upstream gateway does, and only on
the budgeted path.

The outbound request's `model` is rewritten to the provider model. Its
`Authorization` is `Bearer <provider key>`. The run token is not that key.
Every `X-Agenthof-*` header and any `Cookie` are stripped before the request
leaves. The run token authenticates the agent to Agenthof and is never
forwarded upstream.

## What the ledger records

A `model_call` event names the agent, the **logical** model, and a status.
It does not contain the prompt or the completion — not the text, and not a
hash of either.

| Response | `model_call` |
| --- | --- |
| non-streaming 2xx | `succeeded`, with `prompt_tokens` and `completion_tokens` when the body carries `usage` (a present 0 is distinct from absent) |
| `text/event-stream` | `started`. The stream is relayed. Token counts are not captured |
| HTTP 429 | `refused`, reason `budget`. The status is relayed to the agent |
| other non-2xx | `refused`, reason `upstream <code> <status text>` (e.g. `upstream 500 Internal Server Error`). The upstream's own body/reason phrase is not copied into the event |
| body over 10 MiB | `failed`, reason `upstream response too large`, and the agent sees 502 |
| logical name not allowed | `refused`, and the provider is not called |
| no route for that name | `failed`, reason `model route not resolved`, and the agent sees 502 |
| the call never completes (provider unreachable, DNS/timeout, or the response is cut off) | `failed`, reason `model call did not complete`, and the agent sees 502 |

A request body over 1 MiB is rejected before any of that, with no event.

## Honest limits

Agenthof is on the path only for an agent that sends the call to the proxy
URL. A non-conforming agent that already holds a provider key can call the
provider directly. The operator's sandbox — no egress except to Agenthof's
gateways — is what prevents that, and Agenthof does not verify the sandbox.
That is the same limit as the tool and exec doors.

Streamed calls are recorded without token usage. Reading usage off the
stream is reserved. Non-streaming calls record usage when the provider
sends it.

An agent may use exactly its one declared model. A per-role list of models
is reserved. OAuth-protected model providers are reserved; today the key is
the per-role upstream key or the env key named on the route.

`examples/model-agent` is an optional agent that makes this one call. The
quickstart's `examples/echo-agent` does not. model-agent needs an
OpenAI-compatible endpoint in `gateway.models`.
