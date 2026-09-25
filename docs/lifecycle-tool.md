# The life of a tool call

One MCP tool call, from the moment a fronted agent asks for a tool until the
ledger line that records it. This is the tool door. For the run it happens
inside, see [`lifecycle.md`](lifecycle.md). For the YAML, see
[`reference/config.md`](reference/config.md#tools-1). For the executable proof —
a real upstream MCP server, the injected credential, and the rendered
`tool_call` audit line — see the testscript
[`cmd/agenthof/testdata/script/door_tool.txtar`](../cmd/agenthof/testdata/script/door_tool.txtar).

```
  agent                         Agenthof                     MCP resource
    |                               |  step starts:              |
    |                               |  connect, list tools ----> |
    |                               |  mirror them inbound       |
    |  tools/list                   |                            |
    |  Authorization: Bearer        |                            |
    |    <run token>                |                            |
    | <-- the mirrored tools        |                            |
    |                               |                            |
    |  tools/call {name, args}      |-- mirrored? no             |
    |                               |   → tool_call refused ------------> ledger
    |                               |   yes                      |
    |                               |-- inject the resource's    |
    |                               |   credential               |
    |                               |   tools/call ------------> |
    |                               |        (never the run token)
    |                               | <-- result (or error) ---- |
    | <-- relayed result            |-- tool_call ---------------------> ledger
```

## When the door exists

An agent's `tools:` list names one or more tool resources from `gateway.yaml`.
An entry that names no such resource is rejected at `apply`. Every fronted
step already gets a listener on `127.0.0.1` and an ephemeral port (a Unix
socket when `gateway.refbox_socket_dir` is set), plus the two headers
`X-Agenthof-Proxy-URL` and `X-Agenthof-Run-Token`. When the agent declares
tools, that same listener also serves an inbound MCP server at the proxy
URL's root path.

Before the step is handed to the agent, Agenthof connects out to each named
resource as an MCP client, asks it for its tools, and mirrors them onto the
inbound server. Resources are visited in the order the agent declared them,
and each id is visited once. Connecting and listing are bounded at 30
seconds each.

If any of that fails — the resource is unreachable, it will not list its
tools, or two declared resources advertise a tool of the same name — the step
fails outright, with `step_failed` and a reason beginning `tool proxy:`, and
the workflow finishes failed. It does not bounce back to a prior step.

When the step ends, Agenthof shuts the listener down and closes every
upstream connection. The run token stops working. It is never written to the
ledger and never placed on the delegation binding.

## What the agent can see

Naming a resource grants **every tool that resource advertises**. Agenthof
mirrors the upstream's own tool list as it comes back, names and schemas
unchanged. It does not filter within a resource, and it does not invent
tools of its own.

The agent connects to the inbound server holding **only the run token**.
Every request must carry `Authorization: Bearer <run token>`; a missing or
wrong token is rejected before a single MCP message is parsed, and the
comparison is constant-time. The agent never receives the resource's
credential, is never told what it is, and has no route to it.

## Making a call

The agent sends `tools/call` with a tool name and arguments.

- **A name that was never mirrored** — a tool no declared resource
  advertises, or one belonging to a resource this agent did not declare — is
  not forwarded. The ledger records a `tool_call` with status `refused` and
  reason `tool is not available to this run`.
- **A mirrored name** is forwarded to the resource it came from. The
  arguments are passed through untouched.

On the way out, Agenthof's own MCP client sets the request's `Authorization`
to the resource's credential, resolved through the broker on every outbound
request: for `credential_source: static_env` that is the value of the
resource's `token_env` variable; for `grant_type: client_credentials` it is
an upstream token the broker mints itself and refreshes before it expires.
Resolving per request, rather than once at connect, is what lets a token that
expires mid-step be replaced. The agent's run token is never forwarded in
that credential's place.

This is enforcement by credential-starvation, not by inspection: the agent
reaches the resource through this door because it holds nothing else that
the resource would accept.

## What the ledger records

One `tool_call` event per call — forwarded or refused.

| Field | What it holds |
| --- | --- |
| `tool` | the tool name called, or attempted |
| `args_sha` | the SHA-256 of the raw arguments. The arguments themselves are never recorded |
| `auth_mode` | how the resource's credential was obtained: `static_env` or `client_credentials` |
| `resources_touched` | the id of the resource the call went to |
| `artifact_sha` | the SHA-256 of the result |
| `artifact` | a single-line preview of the result, capped at 200 characters |
| `status` | `succeeded`, `failed`, or `refused` |

| What happened | `tool_call` |
| --- | --- |
| the resource returned a result | `succeeded` |
| the resource flagged its result an error | `failed`, reason taken from that result's own text, capped at 200 characters |
| the call did not complete (transport error, timeout) | `failed`, reason from the error, and the agent sees the same failure |
| the name was never mirrored | `refused`, reason `tool is not available to this run`. Nothing is forwarded, and the event names no resource or auth mode, because the call was never tied to one |
| the call arrives while the step is being torn down | the agent gets an error result, `tool proxy is shutting down`, and no event is written |

`audit <run-id>` renders a forwarded call as
`tool echo — args abcdef12 (static_env)`, with the first eight hex characters
of `args_sha`. A refused or failed call renders as `tool <name> refused —
<reason>` or `tool <name> failed — <reason>`.
The event carries the run's delegation binding, like every other event.

Never in the event: the arguments, the full result body, the run token, or
the resource's credential.

## Honest limits

Agenthof is on the path only for an agent that uses this door. A
non-conforming agent that already holds a credential for some other service
can call it directly. The operator's sandbox — no egress except to
Agenthof's gateways — is what prevents that, and Agenthof does not verify
the sandbox. That is the same limit as the model and exec doors.

What the upstream MCP server does with a call, once Agenthof has forwarded
it, is outside Agenthof's control. The door governs which tools the agent
can reach and records what it asked for; it does not constrain what the tool
then does.

A refused `tool_call` is first-hand evidence that the attempt reached this
door. An agent that ignores the proxy entirely leaves no such record.

The event joins the run's hash-chained ledger. What that chain does and does
not prove is the same limit as every other event; see
[`lifecycle.md`](lifecycle.md).

## What ships today vs what is reserved

| Shipped today | Reserved for later |
| --- | --- |
| naming a resource grants every tool it advertises | per-tool selection inside a resource — an allowlist of which of its tools the agent may see |
| an HTTP (streamable) MCP transport | a stdio transport, where the MCP server would be a local subprocess |
| `static_env` and `client_credentials` credentials, injected outbound | read-only versus mutating scope — a grant does not today distinguish a tool that reads from one that writes |

Only shipped behavior is a guarantee.
