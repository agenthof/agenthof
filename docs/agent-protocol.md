# The agent protocol

An Agenthof agent is an **external HTTP service you write**. Agenthof does not run
your agent's code; it calls your agent over HTTP (or a Unix socket) and expects it to
answer a small JSON contract. Any language that can serve HTTP and parse JSON can be an
Agenthof agent — this page is the core of the contract (a few optional headers are noted
at the end).

Reference implementations: [`examples/echo-agent`](../examples/echo-agent) (Go, echoes
its input and shows both the TCP and `unix://` gateway forms) and
[`examples/model-agent`](../examples/model-agent) (Go, makes one model call over TCP).

## The one rule: an agent needs no credentials

Agenthof exists so an agent **needs no** provider key, tool credential, or command
authority of its own. When it needs a model, a tool, or a command, it calls back through
the **gateway** Agenthof gives it for the current step, authenticating with a **per-run
token** — Agenthof injects the real credential upstream, and your agent never sees it.
(Agenthof does not *verify* that your agent holds no other credentials; a non-conforming
agent that smuggled in a key could still call out — stopping that is the operator's
sandbox's job. See [`docs/concepts.md`](concepts.md).)

## A step

For each step of a workflow, Agenthof `POST`s your agent's endpoint a JSON body:

```json
{
  "input": "the step input (string)",
  "artifacts": { "prior-output-name": "value" },
  "agent": "the agent name from config"
}
```

- `input` — the input for this step.
- `artifacts` — outputs of earlier steps, **keyed by the producing agent's `output`
  name** (not the step name; an agent with no `output` contributes nothing). Always
  present — `{}` on the first step.
- `agent` — the configured name of the agent being invoked.

Your agent replies `200 OK` with a JSON body:

```json
{
  "artifact": "this step's output (string)",
  "success": true,
  "reason": "why it failed (only when success is false)"
}
```

- `artifact` — the step's output; passed to later steps and **stored in the artifact
  store, with a preview and hash recorded in the ledger**.
- `success` — `true` if the step succeeded. On `false`, the engine bounces back to the
  step's `on_failure` target (default: the previous step) up to `max_bounces` times
  (default 2); only the first step, or an exhausted bounce budget, fails the run.
- `reason` — a short explanation, included only on failure (truncated past ~300 chars).

### Limits the engine enforces (so a step doesn't silently hang)

- Anything other than `200 OK` is a **failed step** (Agenthof does **not** follow 3xx
  redirects).
- The response body is capped at **1 MiB**.
- The whole step round-trip has a budget (default **5 minutes**); a transport error or
  timeout is a failed step.

See [`docs/lifecycle.md`](lifecycle.md) for the full step lifecycle.

## Reaching a door (model, tool, exec)

To use a model, a tool, or a command, your agent calls the **gateway** for the current
step. Agenthof passes two request headers on the step `POST`:

- `X-Agenthof-Proxy-URL` — the base URL of the per-run gateway.
- `X-Agenthof-Run-Token` — a token scoped to this run; use it as a bearer to the
  gateway. It is **not** a provider key and is worthless anywhere else.

The proxy URL is usually `http://host:port/` (note the **trailing slash** — strip it
before appending a path, or you get `//v1/...`, which the gateway answers with a `307`
the client may not follow). Inside a no-network sandbox like
[refbox](../deploy/refbox) it is a `unix://<socket-path>` address (no trailing slash); if
your agent runs there, dial the Unix socket instead of a TCP host (`echo-agent` shows
both).

### Model door — an OpenAI-compatible chat completion

`POST <proxy-url>/v1/chat/completions` with `Authorization: Bearer <run-token>` and an
OpenAI-style body. Use the **logical** model name your agent is configured with (e.g.
`fast`); an agent with no `model:` must send the gateway's `defaults.model`. **Any other
name is refused with `403` and recorded as a `refused` `model_call`** — Agenthof maps the
logical name to a provider and injects the provider key, so you cannot pick an arbitrary
provider model here.

```
POST  {proxy-url}v1/chat/completions      # proxy-url already ends in / for TCP
      Authorization: Bearer {run-token}
      { "model": "fast", "messages": [ { "role": "user", "content": "..." } ] }
```

Read the reply from `choices[0].message.content`. **Only `/v1/chat/completions` is
served** — other OpenAI paths (`/v1/models`, `/v1/embeddings`, …) are not, so point a
framework's LLM client at the chat-completions path specifically and set its key to the
run token. Streamed responses are relayed but recorded without token counts (see
[`docs/lifecycle-model.md`](lifecycle-model.md)).

### Tool door — MCP over the gateway

The gateway serves a **Model Context Protocol** (Streamable HTTP) endpoint at the proxy
URL's root. Connect an MCP client to `<proxy-url>` with `Authorization: Bearer
<run-token>` and call tools as usual; Agenthof enforces the per-agent tool allowlist and
injects the resource's credential (one credential per resource). Your agent sees only the
tools it was granted.

### Exec door — attested

To run an allowlisted command, an agent (whose config declares `exec: {mode: attested,
allow: [...]}`) calls `POST <proxy-url>/exec/authorize` with `{"command": [argv]}` → `200
{"allowed": bool}` (200 even when refused), then, after running the command itself, `POST
<proxy-url>/exec/attest` with `{"command": [...], "exit": <int>, "output_sha": "..."}` →
`204`. The exec door is *attested*: Agenthof authorizes and records the reported command;
containment of what actually runs is the operator's sandbox's job. See
[`docs/lifecycle-exec.md`](lifecycle-exec.md).

## Configuring your agent

Point an agent's `endpoint` at where your service listens (see
[`docs/reference/config.md`](reference/config.md)). `http://` is accepted only to a
loopback host (`localhost`/`127.0.0.1`/`::1`); otherwise use `https` or `unix://`.

```yaml
name: my-agent
execution: fronted
endpoint: http://127.0.0.1:8080/     # or unix:///path/to/agent.sock
model: fast                          # the logical model this agent may use
output: my-result                    # names this agent's artifact for later steps
```

## Optional: identity headers

Beyond the two gateway headers, every step `POST` also carries context headers your
agent may read but does not need to function: `X-Agenthof-Agent`, `X-Agenthof-Invoker`,
`X-Agenthof-Invoker-Issuer`, `X-Agenthof-Invoker-Method`, `X-Agenthof-Role`,
`X-Agenthof-Workflow`, `X-Agenthof-Run-Id`, plus a signed `X-Agenthof-Binding-Signature`.
See [`docs/lifecycle.md`](lifecycle.md).

## What is stable

The step request/response shape, the two gateway headers, and the model
(`/v1/chat/completions`) and tool (MCP) paths are the wire contract — write to them, not
to any internal detail.
