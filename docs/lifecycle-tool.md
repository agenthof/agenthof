# The life of a tool call

One MCP tool call, from the moment a fronted agent asks for a tool until the
ledger line that records it. This is the tool door. For the run it happens
inside, see [`lifecycle.md`](lifecycle.md). For the YAML, see
[`reference/config.md`](reference/config.md#tools-1). For the executable proof —
a real upstream MCP server, the injected credential, and the rendered
`tool_call` audit line — see the testscripts
[`cmd/agenthof/testdata/script/door_tool.txtar`](../cmd/agenthof/testdata/script/door_tool.txtar)
(a `mode: all` grant) and
[`cmd/agenthof/testdata/script/door_tool_allowlist.txtar`](../cmd/agenthof/testdata/script/door_tool_allowlist.txtar)
(a grant restricted to named tools, with the left-out tool refused).
For a stdio-only MCP server reached through the reference bridge, see
[`scripts/e2e-refbridge-local.sh`](../scripts/e2e-refbridge-local.sh).

```
  agent                         Agenthof                     MCP resource
    |                               |  step starts:              |
    |                               |  connect, list tools ----> |
    |                               |  mirror the granted ones   |
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

Every fronted step gets a listener on `127.0.0.1` and an ephemeral port (a
Unix socket when `gateway.refbox_socket_dir` is set), plus the two headers
`X-Agenthof-Proxy-URL` and `X-Agenthof-Run-Token`. That listener always
serves an inbound MCP server at the proxy URL's root path, alongside the exec
routes and the model route.

What an agent's `tools:` list changes is **which tools are mirrored onto that
server**. Each entry is an object naming a tool resource from `gateway.yaml`.
An object with `mode: all` grants every tool that resource advertises; a
resource id on its own is not a grant and is rejected at `apply`. An object
with `tools: [list_issues, get_issue]` grants only the
named tools of that resource. An object with `mode: read-only` grants only
the tools the operator lists in that resource's `read_only_tools`; adding a
`tools` list narrows it further, and every name in it must be one of those
read-only tools. A tool not in `read_only_tools` is treated as mutating. An entry that names no such
resource is rejected at `apply`. An agent that declares no tools still gets
the MCP server — with an empty tool list, and any `tools/call` it sends
recorded `refused`, reason `tool is not available to this run`.

Before the step is handed to the agent, Agenthof connects out to each named
resource as an MCP client, asks it for its tools, and mirrors them onto the
inbound server — all of them for a `mode: all` entry, only the
granted ones otherwise; a tool the entry leaves out is treated as if the resource had
never advertised it. Resources are visited in the order the agent declared
them, and each id is visited once. Connecting and listing are bounded at 30
seconds each.

If any of that fails — the resource is unreachable, it will not list its
tools, two declared resources advertise a mirrored tool of the same name, or
an entry's `tools` list names a tool its resource does not advertise (a typo,
or a tool the resource has since dropped), or a `mode: read-only` entry matches
none of the tools the resource advertises — the step fails outright, with
`step_failed` carrying the fixed reason `tool proxy start failed`, and the
workflow finishes failed. It does not bounce back to a prior step. The ledger
reason is fixed and generic on purpose: a start error can wrap the resource's
own URL (query string and injected credential included), which must never
reach an event (Article III). The *specific* cause — which resource, and for a
missing allowlisted tool exactly which name — is named in the operational log
instead, so naming a tool that is not there still fails loudly and debuggably;
it just does so on stderr, not in the ledger. Because a left-out tool is never
mirrored, a name
clash between two resources is only a clash when both sides are actually
granted — restricting one side is a way to resolve it. A name in
`read_only_tools` that the resource no longer advertises is a standing list
entry, not a request, so it is skipped with a warning in the operator's log
rather than failing the step.

When the step ends, Agenthof shuts the listener down and closes every
upstream connection. The run token stops working. It is never written to the
ledger and never placed on the delegation binding.

## What the agent can see

A `mode: all` entry grants **every tool that resource advertises**;
any other entry grants **only the tools it names or the resource's
`read_only_tools`**. Either way Agenthof mirrors the
upstream's own tool definitions as they come back, names and schemas
unchanged. It does not invent tools of its own, and it does not rewrite the
ones it mirrors.

The agent connects to the inbound server holding **only the run token**.
Every request must carry `Authorization: Bearer <run token>`; a missing or
wrong token is rejected before a single MCP message is parsed, and the
comparison is constant-time. The agent never receives the resource's
credential and is never told what it is: through this door there is no path
from the run token to the credential's value. Whether the agent can reach
that value some other way — a shared environment, a network path — is the
operator's sandbox's business, not something this door can promise. See
[Honest limits](#honest-limits).

## Making a call

The agent sends `tools/call` with a tool name and arguments.

- **A name that was never mirrored** — a tool no declared resource
  advertises, one belonging to a resource this agent did not declare, or one
  an object entry left out — is not forwarded. The ledger records a
  `tool_call` with status `refused` and reason `tool is not available to
  this run`.
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

This is enforcement by credential-starvation, not by inspection: Agenthof
never hands the agent a credential of its own, so the door is the only route
to the resource that Agenthof itself provides.

## What the ledger records

A call this door handles — forwarded or refused — is recorded as one
`tool_call` event. The one exception is the last row of the second table
below.

| Field | What it holds |
| --- | --- |
| `tool` | the tool name called, or attempted |
| `args_sha` | the SHA-256 of the raw arguments. The arguments themselves are never recorded |
| `auth_mode` | how the resource's credential was obtained: `static_env` or `client_credentials` |
| `resources_touched` | the id of the resource the call went to |
| `artifact_sha` | the SHA-256 of the result — or, when the call itself failed, of the error text |
| `artifact` | a single-line preview of that same body, capped at 200 characters |
| `runtime_attestation` | only when the resource declares `runtime: refbridge`: the bridge's first-hand account of the call — `runtime`, `session`, `command` (the spawned argv), `pid`, `spawn` (the child's generation within the session), `credential_env` (a variable name), `env_names` (the child's whole environment, names only), `materialization` |
| `status` | `succeeded`, `failed`, or `refused` |

A refused call is recorded before any resource is chosen, so it carries only
`tool`, `args_sha`, `status`, and `reason` — plus the agent name and binding
every event carries. It has no `auth_mode`, no `resources_touched`, and
neither `artifact_sha` nor `artifact`.

| What happened | `tool_call` |
| --- | --- |
| the resource returned a result | `succeeded` |
| the resource flagged its result an error | `failed`, reason taken from that result's own text, capped at 200 characters |
| the call did not complete (transport error, timeout) | `failed`, reason from the error, and the agent sees the same failure. The hash and preview are of that error text |
| the name was never mirrored | `refused`, reason `tool is not available to this run`. Nothing is forwarded |
| the call arrives while the step is being torn down | the agent gets an error result, `tool proxy is shutting down`, and no event is written |

`audit <run-id>` renders a forwarded call as
`tool echo — args abcdef12 (static_env)`, with the first eight hex characters
of `args_sha`. A call attested by a bridge carries a suffix:
`[runtime-attested: refbridge /stdio-tool -credential-env DEMO_TOKEN pid 4242 spawn 1]` —
the runtime, the argv it spawned, the child that answered, and its generation
within the session — on succeeded and failed lines alike. A refused or failed
call renders as `tool <name> refused — <reason>` or `tool <name> failed — <reason>`.
The event carries the run's delegation binding, like every other event.

Never in the event: the arguments, the full result body, the run token, or
the resource's credential.

## A stdio server behind a bridge

Many MCP servers speak only stdio: they are a local command, not a URL.
Agenthof itself never runs a command (Article I), so such a server is
governed through a bridge that lives in the operator's runtime, the way an
agent lives in its sandbox. The reference bridge is `refbridge`
(`deploy/refbridge`: the program and its compartment recipe together).

```
 Agenthof tool door                refbridge (operator's runtime)          stdio server
    |  unix:// socket, only          |                                      |
    |  Agenthof can reach it         |                                      |
    |-- initialize ----------------->|  admit the session (a cap applies)   |
    |-- tools/list ----------------->|  spawn ONE subprocess for this       |
    |   Authorization: Bearer        |  session: clean environment +        |
    |     <resource credential>      |  the credential as one variable ---->| starts
    | <-- the server's tools --------|<-- tools/list ------------------------|
    |-- tools/call ----------------->|-- tools/call ----------------------->|
    | <-- result --------------------|<-- result ---------------------------|
    |-- session ends (DELETE) ------>|  end the subprocess                  | exits
```

To Agenthof the bridge is an ordinary tool resource whose `url` is
`unix://` plus the bridge's socket path. Everything on this page applies
unchanged: the grant, the mirroring, the per-call credential injection,
the `tool_call` event. What the bridge adds:

- **Reachable only by Agenthof.** The socket lives in a directory the bridge
  requires to be mode `0700` and owned by the user it runs as; the bridge
  refuses to start otherwise. That directory is never one an agent
  compartment mounts, and the agent compartment has no network, so the agent
  has no path to the bridge. The bridge does not validate the bearer as a
  caller identity — the directory is the gate.
- **The credential reaches the server as one environment variable, and
  nothing else does.** The subprocess environment is built from an explicit
  list of variable names plus that one variable; an empty list means an
  empty environment. The bridge never inherits its own environment into the
  server.
- **One subprocess per MCP session, never shared.** Agenthof opens one
  session per step, so a step's tool calls go to a subprocess that exists
  for that step alone and is ended when the session ends. A session that is
  never closed (Agenthof stopped without saying so) is ended by the bridge's
  idle timeout, and every session by its maximum lifetime. The number of
  concurrent sessions is capped.
- **Two ways to hand over a credential, chosen in the bridge's config.**
  `env-at-spawn` sets the value from the session's first call and keeps it —
  right for a static bearer. `respawn-on-rotation` is for a rotating
  (`client_credentials`) token: Agenthof injects the current token on every
  call, and when it changes the bridge ends the subprocess and starts a new
  one with the new value before forwarding that call. The subprocess's own
  state resets at that point.
- **Egress is the compartment's.** The bridge config names the hosts the
  server may reach; an empty list runs the compartment with no network at
  all, which is what the reference recipe proves. A non-empty list is
  enforced by a network the operator restricts (`REFBRIDGE_NETWORK`), or
  the recipe refuses.
- **The bridge attests first-hand what it ran.** The bridge is the party
  that built the subprocess's environment, started it, and relayed the
  call, so on every result it hands back it states what it did, and
  Agenthof records that on the `tool_call` event as `runtime_attestation`
  when the resource declares `runtime: refbridge`: the command it spawned,
  the process that answered and its generation within the session (a
  respawn after a rotation is visible as generation 2), the session id, the
  name of the variable the credential went into, and the complete list of
  the subprocess's environment variable names. Names and ids only, never a
  value, and the agent never sees it — Agenthof takes it out of the result
  before the agent does. This is the runtime's own word, not the agent's:
  an exec event's `mode: attested` is what the agent reported, while a
  `runtime_attestation` is what the operator's runtime reports about
  itself. A resource declared `runtime: refbridge` whose result carries no
  such account fails the call, so a recorded stdio call is always an
  attested one.

Every one of these is configuration the bridge requires; a config that
omits any of them is refused before the bridge starts.

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

Through a bridge, what the ledger holds about the stdio hop is the bridge's
own first-hand account (`runtime_attestation`), and it is exactly as
trustworthy as the bridge: a compromised bridge could misreport what it
spawned, as a compromised sandbox could misreport what it contains. That is
the operator-runtime boundary this whole page rests on, not a new one; what
Agenthof adds is that only a resource the operator declared `runtime:
refbridge`, reached over a local socket, can put such an account in the
ledger — a claim on any other resource's result is discarded, never
recorded, never shown to the agent. Two things stay outside it: the
subprocess's exit and teardown are the bridge's log, keyed by the session id
the attestation carries, because they happen after the last result has
gone; and what the server does with its credential upstream is attested by
nobody, exactly as what any upstream MCP server does with a call is outside
this door. Teardown kills the process group the bridge created for the
subprocess, so a descendant that moved itself to another group is not
reached. Whoever can reach the bridge's socket decides which credential its
subprocess gets, so the socket directory's permissions carry that weight.
An allowed egress host is a path the credential can leave through. A
rotating token frozen at spawn can expire before a long step ends; that is
why a rotating credential uses `respawn-on-rotation`, and even then a token
that expires while a single call is in flight fails that call. The bridge
passes the resource's credential on to the server it fronts, which is a
stated deviation from the letter of the MCP authorization rule against
transiting tokens: the token is Agenthof's own resource credential, never a
caller's, delivered over a private socket to the server it was issued for,
so the confused-deputy and audience hazards that rule guards against do not
arise, and the ledger still records the injection.

The event joins the run's hash-chained ledger. What that chain does and does
not prove is the same limit as every other event; see
[`lifecycle.md`](lifecycle.md).

## What ships today vs what is reserved

| Shipped today | Reserved for later |
| --- | --- |
| a grant is `mode: all` (every tool the resource advertises), `mode: read-only` (the resource's `read_only_tools`, as the operator lists them), or a `tools` list (only those names); a resource id on its own is rejected at `apply` | |
| an HTTP (streamable) MCP transport, over TCP or a `unix://` socket; a stdio MCP server through the reference bridge (`deploy/refbridge`), which attests first-hand on every call what it ran (`runtime_attestation`) | a bridge that keeps the credential to itself and relays it onto the server's outbound calls; the subprocess's exit on the ledger |
| `static_env` and `client_credentials` credentials, injected outbound | |

Only shipped behavior is a guarantee.
