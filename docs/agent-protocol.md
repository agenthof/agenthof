# The agent protocol

An Agenthof agent is an **external HTTP service you write**. Agenthof does not run
your agent's code; it calls your agent over HTTP (or a Unix socket) and expects it to
answer a small JSON contract. Any language that can serve HTTP and parse JSON can be an
Agenthof agent — this page is the core of the contract (a few optional headers are noted
at the end).

Reference implementations: [`examples/echo-agent`](../examples/echo-agent) (Go, echoes
its input and shows both the TCP and `unix://` gateway forms),
[`examples/model-agent`](../examples/model-agent) (Go, makes one model call over TCP),
and [`examples/langchain-agent`](../examples/langchain-agent) (Python, LangChain; serves
the contract over TCP or a Unix socket, makes one model call through the gateway in
either form, or — with its scripted driver — drives the model, exec, tool and spawn
doors in one step).

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

## Reaching a door (model, tool, exec, spawn)

To use a model, a tool, a command, or a governed child run, your agent calls the
**gateway** for the current step. Agenthof passes two request headers on the step `POST`:

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

### Exec door — first-hand

An agent whose config declares `exec: {runtime: refexec, url: unix://…, timeout: …,
allow: [...]}` does not run the command: it calls `POST <proxy-url>/exec/run` with
`{"command": [argv]}` and gets `200 {"exit": <int>, "output": "<string>", "truncated":
<bool>}` once the operator's runtime has run it in a no-network compartment on the shared
workspace — or `403` (off the allowlist, or no `exec` declared; recorded) or `502` (the
runtime call failed, recorded). The exec door is *first-hand*: the ledger gets the
runtime's account of what ran, never the agent's. The retired agent-asserted routes
`/exec/authorize` and `/exec/attest` answer `403` on every agent and are recorded as
refusals. See [`docs/lifecycle-exec.md`](lifecycle-exec.md).

### Spawn door — a governed child run

`POST <proxy-url>/spawn` with `Authorization: Bearer <run-token>` and
`{"role": "...", "workflow": "...", "input": "..."}`. Agenthof runs that
workflow as a full governed run under the same human — in compartments of
its own, provisioned by the operator's supervisor — and answers when it is
over:

- `200 {"status": "succeeded" | "failed", "child_run_id", "output_sha",
  "output_preview"}` — the child's final artifact comes back as a hash and a
  short preview, never the body.
- `403 {"status": "refused", "reason", "child_run_id"?}` — the target is not
  on your agent's `may_spawn` list, a cap would be exceeded, the child could
  not be given compartments (`spawn compartment unavailable`), or the child
  was refused at its own registry gate or pre-run gate (then it has a
  `child_run_id` and a ledger). The `reason` is always a fixed, classifying
  string — a registry-gate refusal answers `child refused by its access policy`,
  never the role's required groups; the full reason is in the child's own
  ledger, reached by `child_run_id`.
- `502` — the child could not be carried through (Agenthof could not write
  its ledger, say); recorded on your run's ledger as a failed spawn.
- `503` — the step was already over when the request arrived.

The call blocks for the child's duration, so your HTTP client must not time
it out sooner than the step's own deadline. Several concurrent calls run
children in parallel, up to `max_parallel`. A child may call `/spawn` too,
up to `max_depth`. Inside a child, your agent is dialed at the compartment
the supervisor gave it and its exec door reaches the child's own runtime,
whatever its YAML names. Which targets you may spawn, and every bound, is
config — see [`may_spawn`](reference/config.md#may_spawn) and
[the life of a spawn](lifecycle-spawn.md). The identity headers a child
receives carry `X-Agenthof-Run-Id` for the child's own run; the binding is
forwarded, not signed.

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
`X-Agenthof-Workflow`, `X-Agenthof-Run-Id`. The delegation binding is
**forwarded** on every step this way — attested, not enforced: nothing
cryptographically binds these headers today, so treat them as context, not
as proof. Cryptographically signing the binding is reserved for later, not
a current guarantee. See [`docs/lifecycle.md`](lifecycle.md).

## What is stable

The step request/response shape, the two gateway headers, and the model
(`/v1/chat/completions`), tool (MCP), exec (`/exec/*`) and spawn (`/spawn`) paths are
the wire contract — write to them, not to any internal detail.
