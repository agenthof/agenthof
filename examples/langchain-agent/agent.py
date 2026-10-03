#!/usr/bin/env python3
"""A LangChain agent that runs governed under Agenthof.

It serves Agenthof's step contract — POST {"input", "artifacts", "agent"} →
{"artifact", "success", "reason"} — on a TCP address or a Unix socket, and
answers each step with ONE model call made through the per-run gateway that
Agenthof names in the X-Agenthof-Proxy-URL header, authenticated with the
X-Agenthof-Run-Token. It holds no provider key: the gateway injects that
upstream. Inside a no-network compartment (deploy/refbox) the proxy URL is
unix://<socket-path>; elsewhere it is http://127.0.0.1:<port>/.

Dependencies: the standard library plus langchain-openai (which brings httpx) and mcp.
"""
import argparse
import asyncio
import json
import os
import socketserver
import sys
from collections import namedtuple
from http.server import BaseHTTPRequestHandler

import httpx
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

# Same cap as Agenthof's adapter puts on the reply it will read from us.
MAX_BODY = 1 << 20
# Below the engine's 5-minute step budget, so this agent reports a failed
# step itself rather than the adapter timing out on it.
REQUEST_TIMEOUT = 240
UNIX = "unix://"


def gateway_client(proxy_url):
    """Return (base_url, http_client) for the OpenAI client behind ChatOpenAI.

    unix://<path>  → an httpx client whose transport dials that socket; the
                     base URL's host is a placeholder (the gateway ignores it;
                     only the /v1/... route matters).
    http(s)://...  → the URL with its trailing slash stripped, so appending
                     /v1 hits /v1/chat/completions directly instead of
                     bouncing through a 307 redirect; no custom client.
    """
    if proxy_url.startswith(UNIX):
        transport = httpx.HTTPTransport(uds=proxy_url[len(UNIX):])
        return "http://localhost/v1", httpx.Client(transport=transport, timeout=REQUEST_TIMEOUT)
    if proxy_url.startswith(("http://", "https://")):
        return proxy_url.rstrip("/") + "/v1", None
    raise ValueError("unsupported proxy URL scheme")


def make_llm(proxy_url, run_token, model):
    base_url, client = gateway_client(proxy_url)
    kwargs = {
        "base_url": base_url,
        "api_key": run_token,   # the per-run token, not a provider key
        "model": model,         # the LOGICAL name; anything else is refused with 403
        "max_retries": 0,
        "timeout": REQUEST_TIMEOUT,
        # The gateway serves only /v1/chat/completions. Never let the SDK
        # choose the Responses API (a silent 404 otherwise).
        "use_responses_api": False,
    }
    if client is not None:
        kwargs["http_client"] = client
    return ChatOpenAI(**kwargs)


def call_model(proxy_url, run_token, model, text):
    """One governed model call: the step input in, the reply text out."""
    llm = make_llm(proxy_url, run_token, model)
    chain = ChatPromptTemplate.from_messages([("user", "{input}")]) | llm | StrOutputParser()
    try:
        return chain.invoke({"input": text})
    finally:
        if llm.http_client is not None:
            llm.http_client.close()


class DoorError(Exception):
    """A door answered with anything but success. Its text is for the
    operator's log only; the step reply carries a fixed reason."""


# The MCP tool door is the gateway's root (/): a standard streamable-HTTP MCP
# server. The official mcp SDK speaks it; the 1.x line pinned in
# requirements.txt opens the session at a protocol version the gateway
# accepts. Over unix:// the SDK's httpx client is built with a Unix-socket
# transport and the URL's host is a placeholder the gateway ignores.
ToolReport = namedtuple("ToolReport", "protocol_version tool_names results")
# The MCP transports' own timeouts: 30s to connect/write, 300s to read, since
# the server may hold a response stream open. Redirect following stays at the
# httpx default (off) — the SDK follows same-origin redirects itself.
DOOR_TIMEOUT = httpx.Timeout(30.0, read=300.0)


def mcp_endpoint(proxy_url, run_token=""):
    """Return (url, http_client) for the MCP door behind proxy_url."""
    if proxy_url.startswith(UNIX):
        url = "http://localhost/"
        transport = httpx.AsyncHTTPTransport(uds=proxy_url[len(UNIX):])
    elif proxy_url.startswith(("http://", "https://")):
        url = proxy_url.rstrip("/") + "/"
        transport = None
    else:
        raise ValueError("unsupported proxy URL scheme")
    client = httpx.AsyncClient(transport=transport, timeout=DOOR_TIMEOUT,
                               headers={"Authorization": "Bearer " + run_token})
    return url, client


async def _tool_session(proxy_url, run_token, calls):
    url, client = mcp_endpoint(proxy_url, run_token)
    results = []
    # The client is the outermost context: the SDK does not own a client it was
    # handed, so closing it is ours, and it has to outlive the transport.
    async with client, streamable_http_client(url, http_client=client) as (read, write, _):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            listed = await session.list_tools()
            for name, args in calls:
                res = await session.call_tool(name, args)
                text = " ".join(c.text for c in res.content if getattr(c, "type", "") == "text")
                if res.isError:
                    raise DoorError("tool %s returned an error" % name)
                results.append(text)
    # Leaving the contexts ends the session: the SDK sends the DELETE, then the
    # streams and the client close, so nothing of it lingers once the step has
    # returned.
    return ToolReport(init.protocolVersion, sorted(t.name for t in listed.tools), results)


def tool_session(proxy_url, run_token, calls):
    """Open ONE MCP session on the gateway, list its tools, make each
    (name, arguments) call in order, close the session; a ToolReport. The
    listing is kept on every step on purpose: it is the agent's own check
    that the grant mirrored the tools it is about to call (what the unit
    test asserts), and it is one cheap request on a session already open."""
    return asyncio.run(_tool_session(proxy_url, run_token, calls))


def call_tools(proxy_url, run_token, calls):
    """The tool door: the text of each call's result, in order."""
    return tool_session(proxy_url, run_token, calls).results


class StepHandler(BaseHTTPRequestHandler):
    server_version = "langchain-agent/0"

    def address_string(self):
        # A Unix-socket peer has no host:port; the default indexes client_address[0].
        return self.client_address[0] if isinstance(self.client_address, tuple) else "unix"

    def log_message(self, fmt, *args):
        sys.stderr.write("langchain-agent: " + (fmt % args) + "\n")

    def _plain(self, status, text):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._plain(405, "method not allowed")

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._plain(400, "bad request")
            return
        if length < 0:
            self._plain(400, "bad request")
            return
        if length > MAX_BODY:
            self._plain(413, "request body too large")
            return
        try:
            step = json.loads(self.rfile.read(length))
        except ValueError:  # JSONDecodeError and bad UTF-8 are both ValueErrors
            self._plain(400, "bad request")
            return
        if not isinstance(step, dict) or not isinstance(step.get("input"), str):
            self._plain(400, "bad request")
            return

        proxy_url = self.headers.get("X-Agenthof-Proxy-URL", "")
        run_token = self.headers.get("X-Agenthof-Run-Token", "")
        if not proxy_url or not run_token:
            self._json({"artifact": "", "success": False, "reason": "model proxy coordinates missing"})
            return
        try:
            reply = self.server.call_model(proxy_url, run_token, self.server.model, step["input"])
        except Exception as exc:  # noqa: BLE001 — any failure is a failed step
            # The reason is fixed: exception text can carry the proxy URL, the
            # token, or upstream error bodies, none of which belong in a ledger.
            self.log_message("model call failed: %s", type(exc).__name__)
            self._json({"artifact": "", "success": False, "reason": "model call failed"})
            return
        self._json({"artifact": reply, "success": True})


class _Threaded(socketserver.ThreadingMixIn):
    daemon_threads = True


class TCPStepServer(_Threaded, socketserver.TCPServer):
    allow_reuse_address = True


class UnixStepServer(_Threaded, socketserver.UnixStreamServer):
    def server_close(self):
        super().server_close()
        try:
            os.unlink(self.server_address)
        except FileNotFoundError:
            pass


def make_server(socket_path, addr, model, call_model=call_model):
    """Serve the step contract on socket_path (Unix) when given, else on addr (host:port)."""
    if socket_path:
        try:
            os.unlink(socket_path)  # a stale file from a killed process would make bind fail
        except FileNotFoundError:
            pass
        srv = UnixStepServer(socket_path, StepHandler)
    else:
        host, _, port = addr.rpartition(":")
        srv = TCPStepServer((host, int(port)), StepHandler)
    srv.model = model
    srv.call_model = call_model
    return srv


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="LangChain agent for Agenthof (one governed model call per step)")
    # Single dash on purpose: the refbox recipe appends "-socket <path>" after
    # the image name, and the last -socket given wins.
    p.add_argument("-socket", dest="socket", default="", help="Unix socket path to listen on; overrides --addr")
    p.add_argument("--addr", default="127.0.0.1:8082", help="TCP listen address when -socket is not set")
    p.add_argument("--model", default="fast", help="logical model name this agent is configured with")
    return p.parse_args(argv)


def main(argv=None):
    opts = parse_args(argv)
    srv = make_server(opts.socket, opts.addr, opts.model)
    where = "unix:" + opts.socket if opts.socket else "%s:%d" % srv.server_address[:2]
    sys.stderr.write("langchain-agent listening on %s, logical model %s\n" % (where, opts.model))
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
