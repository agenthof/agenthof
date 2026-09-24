# model-agent

An optional fronted agent that calls a model through Agenthof.

On each step it reads `X-Agenthof-Proxy-URL` and `X-Agenthof-Run-Token` from
the request, sends the step input to `<proxy URL>v1/chat/completions` with
the run token as the bearer, and returns the reply text as its artifact. It
does not hold a provider key. Agenthof injects that key at the model gateway.

This is separate from `examples/echo-agent`, which needs nothing running
except itself. model-agent needs:

- an OpenAI-compatible endpoint configured under `gateway.models` (a local
  LiteLLM is the usual one);
- the agent's `model` (or `gateway.defaults.model`) set to the logical name
  this process was started with (`-model`, default `fast`);
- a role key from `agenthof gateway provision` when you want LiteLLM to
  enforce `budget_usd_month`. With no role key, Agenthof uses the route's
  `api_key_env` and no budget applies.

Point the agent's `endpoint` at this process (`-addr`, default
`127.0.0.1:8081`) and run the workflow. The agent must be the one Agenthof
calls: it only reaches the model door because the run hands it the proxy
coordinates. A process that calls the provider directly is outside this door.

Streamed token counts are not recorded. Budgets are enforced by the
upstream gateway via the per-role key, not by Agenthof itself.
