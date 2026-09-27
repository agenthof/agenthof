# python-agent

A minimal Agenthof fronted agent written in Python, using the **standard library only**
— no `pip install`. It shows that an Agenthof agent is just an HTTP service speaking a
small JSON contract, in any language. The full contract is in
[`docs/agent-protocol.md`](../../docs/agent-protocol.md).

## Run it

By default it **echoes** the step input back as its artifact (like the Go
[`echo-agent`](../echo-agent)), so it needs no model backend and runs the quickstart
hermetically. It listens where the example config points agents (`127.0.0.1:8080`):

```bash
python3 examples/python-agent/agent.py
```

Then, from the repository root, the usual quickstart runs unchanged against it:

```bash
go build -o agenthof ./cmd/agenthof
./agenthof apply --as you@example.com --config examples/config
./agenthof run software-engineer fix-bug --input "fix the login bug" --as you@example.com --config examples/config
./agenthof audit <run-id>
```

The audit shows the three steps succeeding with the input echoed as each artifact —
identical to the Go echo agent, proving the contract is language-agnostic.

## Making a model call

With `--call-model` it makes one chat completion **through Agenthof's model gateway**,
using the per-step proxy URL and run token from the request headers — it holds no
provider key:

```bash
python3 examples/python-agent/agent.py --call-model --model fast
```

This requires a model gateway to be reachable (see [`docs/quickstart.md`](../../docs/quickstart.md));
the credential is injected by Agenthof, never held by this agent. Only the TCP form of
the proxy URL is handled here; a `unix://` proxy URL (used inside
[refbox](../../deploy/refbox)) needs a socket-dialing transport.

## What this is not

A reference example, not an SDK. It implements the wire contract directly so you can see
every part of it. Wrap your own framework agent (LangChain, ADK, …) the same way: serve
the step contract, and route model/tool calls through the gateway named in the headers.
