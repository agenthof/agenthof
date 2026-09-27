# The agent protocol

An Agenthof agent is an **external HTTP service you write**. Agenthof does not run
your agent's code; it calls your agent over HTTP (or a Unix socket) and expects it to
answer a small JSON contract. Any language that can serve HTTP and parse JSON can be an
Agenthof agent — this page is the whole contract.

Reference implementations: [`examples/echo-agent`](../examples/echo-agent) (Go, echoes
its input), [`examples/model-agent`](../examples/model-agent) (Go, makes one model
call), and [`examples/python-agent`](../examples/python-agent) (Python, standard library
only).

## The one rule: an agent holds no credentials

Agenthof exists to keep provider keys, tool credentials, and command authority **out of
the agent**. Your agent never carries an API key. When it needs a model, a tool, or a
command, it calls back through the **gateway** Agenthof gives it for the current step,
authenticating with a **per-run token** — Agenthof injects the real credential upstream,
and your agent never sees it. Everything below follows from that.

## A step

For each step of a workflow, Agenthof sends your agent's endpoint an HTTP `POST` with a
JSON body:

```json
{
  "input": "the step input (string)",
  "artifacts": { "prior-output-name": "value" },
  "agent": "the agent name from config"
}
```

- `input` — the input for this step.
- `artifacts` — outputs of earlier steps, by name; may be empty or absent.
- `agent` — the configured name of the agent being invoked.

Your agent replies `200 OK` with a JSON body:

```json
{
  "artifact": "this step's output (string)",
  "success": true,
  "reason": "why it failed (only when success is false)"
}
```

- `artifact` — the step's output, passed on to later steps and recorded in the ledger.
- `success` — `true` if the step succeeded; `false` marks a step failure (the workflow
  fails or, if configured, falls back).
- `reason` — a short human-readable explanation, included only on failure.

That is the complete contract for an agent that does its own work (like `echo-agent`).
An agent that only transforms its input needs nothing else.

## Reaching a door (model, tool, exec)

To use a model, a tool, or a command, your agent calls the **gateway** for the current
step. Agenthof passes two request headers on the step `POST`:

- `X-Agenthof-Proxy-URL` — the base URL of the per-run gateway.
- `X-Agenthof-Run-Token` — a token scoped to this run; use it as a bearer to the
  gateway. It is **not** a provider key and is worthless anywhere else.

The proxy URL is usually an `http://host:port` address. Inside a no-network sandbox like
[refbox](../deploy/refbox) it is a `unix://<socket-path>` address; if your agent runs
there, dial the Unix socket instead of a TCP host (the Go examples show both).

### Model door — an OpenAI-compatible chat completion

`POST <proxy-url>/v1/chat/completions` with `Authorization: Bearer <run-token>` and an
OpenAI-style body. Use the **logical** model name your agent is configured with (e.g.
`fast`); Agenthof maps it to a provider and injects the provider key.

```
POST  {proxy-url}/v1/chat/completions
      Authorization: Bearer {run-token}
      { "model": "fast", "messages": [ { "role": "user", "content": "..." } ] }
```

Read the reply from `choices[0].message.content`. Because the endpoint is
OpenAI-compatible, an existing framework's LLM client can be pointed at it by setting its
base URL to `<proxy-url>/v1` and its key to the run token — its model calls then flow
through Agenthof, governed and recorded, with no provider key in your agent.

### Tool door — MCP over the gateway

The gateway serves a **Model Context Protocol** (Streamable HTTP) endpoint at the proxy
URL's root. Connect an MCP client to `<proxy-url>` with `Authorization: Bearer
<run-token>` and call tools as usual; Agenthof enforces the per-agent tool allowlist and
injects each tool's credential. Your agent sees only the tools it was granted.

### Exec door — attested

To run an allowlisted command, an agent calls `POST <proxy-url>/exec/authorize` and,
after running the command itself, `POST <proxy-url>/exec/attest` — both with the run
token. The exec door is *attested*: Agenthof authorizes and records the reported command;
containment of what actually runs is the operator's sandbox's job.

## Configuring your agent

Point an agent's `endpoint` at where your service listens (see
[`docs/reference/config.md`](reference/config.md)):

```yaml
name: my-agent
execution: fronted
endpoint: http://127.0.0.1:8080/     # or unix:///path/to/agent.sock
model: fast                          # the logical model this agent may use
```

## What is stable

The step request/response shape, the two gateway headers, and the OpenAI-compatible
model path and MCP tool path are the wire contract — write to them, not to any internal
detail. Language SDKs that wrap this contract are additive and may follow; the protocol
itself is what you build against today.
