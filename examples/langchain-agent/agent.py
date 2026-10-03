#!/usr/bin/env python3
"""A LangChain agent that runs governed under Agenthof.

It serves Agenthof's step contract — POST {"input", "artifacts", "agent"} →
{"artifact", "success", "reason"} — on a TCP address or a Unix socket, and
answers each step with ONE model call made through the per-run gateway that
Agenthof names in the X-Agenthof-Proxy-URL header, authenticated with the
X-Agenthof-Run-Token — or, with `--driver scripted`, every door in a fixed
order — or, with `--driver llm`, a model that is offered the doors as tools
and decides, round by round, which to call. It holds no provider key: the
gateway injects that upstream. Inside a no-network compartment
(deploy/refbox) the proxy URL is unix://<socket-path>; elsewhere it is
http://127.0.0.1:<port>/.

Dependencies: the standard library plus langchain-openai (which brings httpx) and mcp.
"""
import argparse
import asyncio
import concurrent.futures
import json
import os
import socketserver
import sys
import time
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


class StepFailed(Exception):
    """A leg of a driver's sequence failed. reason is the FIXED text the
    step reply carries; cause names the exception class, for the log only."""

    def __init__(self, reason, cause):
        super().__init__(reason)
        self.reason = reason
        self.cause = cause


# --- neutral door layer -------------------------------------------------------
# Plain Python, no LangChain: what any framework's shell wraps. The two door
# tools below are the exec and spawn doors as the model sees them; the MCP
# tools come from the tool door's own listing (list_tools), so a model is
# offered exactly the grant, never a curated subset. Porting the agent to
# another framework means rewriting only the shell below this section.


class DoorError(Exception):
    """A door answered with anything but success. Its text is for the
    operator's log only; the step reply carries a fixed reason. status is the
    HTTP status the door answered with (403 = refused by policy; 502/503 =
    the door could not carry the call; 200 = answered, but the command or
    child itself did not succeed), or None when there was no answer."""

    def __init__(self, text, status=None):
        super().__init__(text)
        self.status = status


def door_base(proxy_url):
    """Return (base_url, httpx.Client) for the gateway's JSON doors
    (/exec/run, /spawn). unix:// dials the socket and the base host is a
    placeholder the gateway ignores; http(s) is used as given."""
    if proxy_url.startswith(UNIX):
        transport = httpx.HTTPTransport(uds=proxy_url[len(UNIX):])
        return "http://localhost", httpx.Client(transport=transport, timeout=REQUEST_TIMEOUT)
    if proxy_url.startswith(("http://", "https://")):
        return proxy_url.rstrip("/"), httpx.Client(timeout=REQUEST_TIMEOUT)
    raise ValueError("unsupported proxy URL scheme")


class Doors:
    """The exec and spawn doors of one step's gateway: one client, closed by
    the caller once the step's calls are over; usable from the threads that
    run parallel spawns."""

    def __init__(self, proxy_url, run_token):
        self.base, self.client = door_base(proxy_url)
        self.headers = {"Authorization": "Bearer " + run_token}

    def close(self):
        self.client.close()

    def _post(self, route, body):
        return self.client.post(self.base + route, json=body, headers=self.headers)

    def exec_run(self, argv):
        """First-hand exec: the gateway has its declared runtime run argv and
        returns the output. Anything but a 200 with exit 0 is a DoorError."""
        resp = self._post("/exec/run", {"command": list(argv)})
        if resp.status_code != 200:
            raise DoorError("exec/run answered %d" % resp.status_code, resp.status_code)
        out = resp.json()
        if out.get("exit") != 0:
            raise DoorError("%s exited %s" % (argv[0], out.get("exit")), 200)
        return out.get("output", "")

    def spawn(self, role, workflow, text):
        """A governed child run; blocks until it is over and returns the
        door's answer (status, child_run_id, output_sha, output_preview) for
        a succeeded child. A refused or failed child is a DoorError: the
        parent's ledger already records it, and a scripted step is a success
        only when every leg was."""
        resp = self._post("/spawn", {"role": role, "workflow": workflow, "input": text})
        if resp.status_code != 200:
            raise DoorError("spawn answered %d" % resp.status_code, resp.status_code)
        out = resp.json()
        if out.get("status") != "succeeded":
            raise DoorError("spawn %s" % out.get("status"), 200)
        return out


# The MCP tool door is the gateway's root (/): a standard streamable-HTTP MCP
# server. The official mcp SDK speaks it; the 1.x line pinned in
# requirements.txt opens the session at a protocol version the gateway
# accepts. Over unix:// the SDK's httpx client is built with a Unix-socket
# transport and the URL's host is a placeholder the gateway ignores.
ToolReport = namedtuple("ToolReport", "protocol_version tool_names results tools")
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
    tools = sorted((ToolSpec(t.name, t.description or "", t.inputSchema) for t in listed.tools), key=lambda t: t.name)
    return ToolReport(init.protocolVersion, [t.name for t in tools], results, tools)


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


ToolSpec = namedtuple("ToolSpec", "name description parameters")

EXEC_TOOL = ToolSpec(
    "exec",
    "Run one allowlisted command through the exec door. command is the argv "
    "(program first, then its arguments). Returns the command's output, or a "
    "fixed refusal when the command is not allowlisted.",
    {"type": "object",
     "properties": {"command": {"type": "array", "items": {"type": "string"},
                                "description": "the argv to run, e.g. [\"env\"]"}},
     "required": ["command"]},
)
SPAWN_TOOL = ToolSpec(
    "spawn",
    "Start one governed sub-agent run through the spawn door and wait for it. "
    "Returns its status, run id and output preview, or a fixed refusal when "
    "the target is not permitted. Call it several times in one turn to run "
    "sub-agents in parallel.",
    {"type": "object",
     "properties": {"role": {"type": "string", "description": "the role the sub-agent runs as"},
                    "workflow": {"type": "string", "description": "the workflow the sub-agent runs"},
                    "input": {"type": "string", "description": "the sub-agent's step input"}},
     "required": ["role", "workflow", "input"]},
)
DOOR_TOOL_NAMES = tuple(t.name for t in (EXEC_TOOL, SPAWN_TOOL))


def list_tools(proxy_url, run_token):
    """The tool door's own listing: the granted tools, with their schemas."""
    return tool_session(proxy_url, run_token, []).tools


def door_tools(mcp_tools):
    """The full tool set a model is offered: the two door tools, then the
    discovered MCP tools. An upstream tool that borrows a door's name would
    make a call ambiguous, so that is a failed step, not a guess."""
    clash = sorted(t.name for t in mcp_tools if t.name in DOOR_TOOL_NAMES)
    if clash:
        raise StepFailed("tool set conflict", "ToolSpec")
    return [EXEC_TOOL, SPAWN_TOOL] + list(mcp_tools)


def openai_tools(specs):
    """The OpenAI function-tool shape every OpenAI-compatible provider speaks."""
    return [{"type": "function",
             "function": {"name": s.name, "description": s.description, "parameters": s.parameters}}
            for s in specs]


def gateway_client(proxy_url):
    """Return (base_url, http_client) for an OpenAI-compatible client (framework-neutral).

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


# --- LangChain shell ----------------------------------------------------------
# The only code that touches LangChain: the model transport. ChatOpenAI points
# at the model door (make_llm), bind_tools puts the neutral tool specs on the
# wire in the OpenAI function shape, and the reply's parsed tool calls come
# back as plain tuples. The conversation itself is a list of OpenAI-style
# dicts, which langchain-core accepts directly, so nothing of LangChain's
# message types leaks out of this section. It ends at the drivers below.
# args is the parsed arguments dict, or None when the model's arguments were
# not a JSON object: the call is still reported, so the caller can answer it
# rather than lose it.
ToolCall = namedtuple("ToolCall", "id name args")
ModelReply = namedtuple("ModelReply", "text tool_calls")


def make_llm(proxy_url, run_token, model, timeout=REQUEST_TIMEOUT):
    base_url, client = gateway_client(proxy_url)
    kwargs = {
        "base_url": base_url,
        "api_key": run_token,   # the per-run token, not a provider key
        "model": model,         # the LOGICAL name; anything else is refused with 403
        "max_retries": 0,
        "timeout": timeout,
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


def invoke_model(proxy_url, run_token, model, messages, tools, timeout=REQUEST_TIMEOUT):
    """One governed model call with the tool set offered; the reply's text
    and parsed tool calls. No tools → a plain chat completion."""
    llm = make_llm(proxy_url, run_token, model, timeout=timeout)
    try:
        runnable = llm.bind_tools(openai_tools(tools)) if tools else llm
        reply = runnable.invoke(messages)
    finally:
        if llm.http_client is not None:
            llm.http_client.close()
    # The SDK splits the model's calls into parsed ones and ones whose
    # arguments did not parse; its split does not keep their interleaving, so
    # the parsed calls come first, then the unparseable ones with args=None.
    calls = [ToolCall(str(c.get("id") or ""), str(c.get("name") or ""), c.get("args") if isinstance(c.get("args"), dict) else None)
             for c in (reply.tool_calls or [])]
    calls += [ToolCall(str(c.get("id") or ""), str(c.get("name") or ""), None)
              for c in (reply.invalid_tool_calls or [])]
    return ModelReply(str(reply.text or ""), calls)


def assistant_message(reply):
    """The model's turn, as the next call will see it. A call whose arguments
    did not parse (args None) is replayed with empty arguments, so the
    conversation stays well-formed."""
    msg = {"role": "assistant", "content": reply.text}
    if reply.tool_calls:
        msg["tool_calls"] = [{"id": c.id, "type": "function",
                              "function": {"name": c.name, "arguments": json.dumps(c.args if c.args is not None else {})}}
                             for c in reply.tool_calls]
    return msg


def tool_message(call, text):
    """One tool result, paired to its call by id."""
    return {"role": "tool", "tool_call_id": call.id, "content": text}


# The drivers: how a step is answered. "model" is one governed model call
# (the reply is the artifact). "scripted" runs the five doors in a fixed
# order and reports each in the artifact — a deterministic sequence an
# audit can be checked against. "llm" is a model deciding, round by round,
# which doors to call (run_llm).
DRIVERS = ("model", "scripted", "llm")

Scripted = namedtuple("Scripted", "exec_argv obo_tool bridge_tool spawn_role spawn_workflow spawns")


def _leg(reason, fn, *args):
    try:
        return fn(*args)
    except Exception as exc:  # noqa: BLE001 — any failure is this leg's fixed reason
        raise StepFailed(reason, type(exc).__name__) from exc


def _artifact_line(text):
    """One ledger line: collapse whitespace so upstream text cannot forge extra lines."""
    return " ".join(str(text).split())


def run_scripted(proxy_url, run_token, model, text, scripted,
                 call_model=call_model, call_tools=call_tools, doors_factory=Doors):
    """The scripted driver: one model call, one first-hand exec, one call on
    the on-behalf-of tool, one on the bridged tool, then scripted.spawns
    parallel sub-agent runs — in that order — and the artifact that reports
    each. The first failing leg ends the step with that leg's fixed reason;
    nothing after it runs. The tool results go into the artifact on purpose:
    what the upstream answered is the step's evidence."""
    lines = ["model: " + _artifact_line(_leg("model call failed", call_model, proxy_url, run_token, model, text))]
    doors = doors_factory(proxy_url, run_token)
    try:
        output = _leg("exec call failed", doors.exec_run, scripted.exec_argv)
        lines.append("exec: " + _artifact_line(output))
        results = _leg("tool call failed", call_tools, proxy_url, run_token,
                       [(scripted.obo_tool, {}), (scripted.bridge_tool, {"text": text})])
        if len(results) != 2:
            raise StepFailed("tool call failed", "short result")
        lines.append("tool %s: %s" % (scripted.obo_tool, _artifact_line(results[0])))
        lines.append("tool %s: %s" % (scripted.bridge_tool, _artifact_line(results[1])))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, scripted.spawns)) as pool:
            futures = [pool.submit(doors.spawn, scripted.spawn_role, scripted.spawn_workflow, text)
                       for _ in range(scripted.spawns)]
            children = _leg("spawn call failed", lambda: [f.result() for f in futures])
    finally:
        doors.close()
    for child in sorted(children, key=lambda c: c["child_run_id"]):
        lines.append("spawn: %s %s %s" % (_artifact_line(child["status"]), _artifact_line(child["child_run_id"]),
                                          _artifact_line(child.get("output_preview", ""))))
    return "\n".join(lines)


# --- the llm driver -----------------------------------------------------------
Llm = namedtuple("Llm", "scripted max_rounds step_budget")

# What the model is fed back when a door did not answer with a result. Fixed
# strings on purpose: a door's error body can carry the proxy URL or an
# upstream's text, and the model's conversation ends up in the provider's
# hands. The ledger holds the first-hand record of each refusal and failure.
REFUSED = "refused by policy"
FAILED = "the door call failed"
UNKNOWN_TOOL = "unknown tool"
INVALID_ARGS = "invalid arguments"
# A tool result fed back to the model is cut here; the full output is on the
# door's own ledger event (exec) or at the upstream, never only in the model's
# view. The whole request (the conversation and the tool specs sent with it) is
# checked against CONVERSATION_MAX before each model call: the model door caps
# a request body at 1 MiB and answers an oversized one with 400 and no ledger
# event, so the agent must stop first. The check is an estimate of the body
# the SDK builds; the margin to the door's cap absorbs the SDK's own framing.
TOOL_RESULT_MAX = 8192
CONVERSATION_MAX = 512 << 10
# The most door calls of one round in flight at once; the rest of the round
# queues behind them, so a model asking for hundreds cannot open hundreds.
MAX_PARALLEL_CALLS = 8


def task_prompt(scripted, text):
    """The system instruction: the task the showcase and the e2e expect a
    capable model to solve by using every door, in plain words. The step
    input is the user message; text is repeated here only through the flags
    that name what to call, never verbatim."""
    return (
        "You are an agent running under Agenthof. Everything you can do is one of the tools offered to "
        "you; each call goes through a governed door and is recorded. A refused call comes back as a fixed "
        "refusal: do not retry it, go on with the rest. Complete this task, then answer with one short "
        "sentence saying what you did.\n"
        "1. Run the command %s with the exec tool.\n"
        "2. Call the tool %s with no arguments.\n"
        "3. Call the tool %s with its text set to the step input.\n"
        "4. Start %d sub-agents with the spawn tool, role %s, workflow %s, input set to the step input, "
        "all in the same turn so they run in parallel.\n"
        "The step input is the user message."
        % (json.dumps(scripted.exec_argv), scripted.obo_tool, scripted.bridge_tool,
           scripted.spawns, scripted.spawn_role, scripted.spawn_workflow)
    )


def _truncate(text):
    text = str(text)
    if len(text) <= TOOL_RESULT_MAX:
        return text
    return text[:TOOL_RESULT_MAX] + " [truncated]"


def _bounded_line(text):
    """Model-chosen text (a tool name, the final answer) as one bounded artifact line."""
    return _artifact_line(_truncate(text))


def _label(name):
    """The artifact label of one door call."""
    return name if name in DOOR_TOOL_NAMES else "tool " + name


def _door_call(call, doors, mcp_names, call_tools, proxy_url, run_token, deadline):
    """One tool call the model made, carried to its door; the text the model
    gets back, or None when the step deadline passed before the call could
    start. Never raises: a door's refusal or failure is a fixed string."""
    if time.monotonic() >= deadline:
        return None
    args = call.args
    if not isinstance(args, dict):
        return INVALID_ARGS
    try:
        if call.name == EXEC_TOOL.name:
            argv = args.get("command")
            if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
                return INVALID_ARGS
            return _truncate(doors.exec_run(argv))
        if call.name == SPAWN_TOOL.name:
            role, workflow, text = (args.get(k) for k in ("role", "workflow", "input"))
            if not (isinstance(role, str) and role and isinstance(workflow, str) and workflow and isinstance(text, str)):
                return INVALID_ARGS
            child = doors.spawn(role, workflow, text)
            return _truncate("succeeded %s %s" % (child.get("child_run_id", ""), child.get("output_preview", "")))
        if call.name in mcp_names:
            return _truncate(call_tools(proxy_url, run_token, [(call.name, args)])[0])
        return UNKNOWN_TOOL
    except DoorError as exc:
        fixed, cause = (REFUSED if exc.status == 403 else FAILED), type(exc).__name__
    except Exception as exc:  # noqa: BLE001 — any failure is the fixed string; the class goes to the log
        fixed, cause = FAILED, type(exc).__name__
    sys.stderr.write("langchain-agent: %s %s: %s\n" % (_bounded_line(_label(call.name)), fixed, cause))
    return fixed


def run_llm(proxy_url, run_token, model, text, llm,
            invoke_model=invoke_model, list_tools=list_tools, call_tools=call_tools, doors_factory=Doors):
    """The llm driver: a model, offered the two door tools and the tools the
    tool door actually grants, decides each round which to call; the round's
    calls run concurrently through the neutral door clients, their results go
    back to the model, and the model's first reply without tool calls is the
    answer. Bounded by llm.max_rounds and llm.step_budget seconds — no model
    or door call starts past the deadline; one already running finishes — and
    by CONVERSATION_MAX. The artifact is one line per leg, in order: it is the
    agent's own summary; the door events on the ledger are the first-hand
    record."""
    deadline = time.monotonic() + llm.step_budget
    tools = door_tools(_leg("tool call failed", list_tools, proxy_url, run_token))
    mcp_names = {t.name for t in tools if t.name not in DOOR_TOOL_NAMES}
    tools_size = len(json.dumps(openai_tools(tools)))  # sent with every request; fixed for the step
    messages = [{"role": "system", "content": task_prompt(llm.scripted, text)},
                {"role": "user", "content": text}]
    lines = []
    doors = doors_factory(proxy_url, run_token)
    try:
        for _ in range(llm.max_rounds):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StepFailed("step deadline reached", "deadline")
            if len(json.dumps(messages)) + tools_size > CONVERSATION_MAX:
                raise StepFailed("conversation too large", "size")
            try:
                reply = _leg("model call failed", invoke_model, proxy_url, run_token, model, messages, tools,
                             min(REQUEST_TIMEOUT, remaining))
            except StepFailed as exc:
                # The call's timeout is the budget left, so a call cut off by
                # the deadline fails as the deadline, not as the model.
                if time.monotonic() < deadline:
                    raise
                sys.stderr.write("langchain-agent: model call cut off by the step deadline: %s\n" % exc.cause)
                raise StepFailed("step deadline reached", "deadline") from exc
            if not reply.tool_calls:
                lines.append("model: " + _bounded_line(reply.text))
                return "\n".join(lines)
            lines.append(_bounded_line("model: called " + ", ".join(c.name for c in reply.tool_calls)))
            messages.append(assistant_message(reply))
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(reply.tool_calls), MAX_PARALLEL_CALLS)) as pool:
                futures = [pool.submit(_door_call, c, doors, mcp_names, call_tools, proxy_url, run_token, deadline)
                           for c in reply.tool_calls]
                results = [f.result() for f in futures]
            if any(r is None for r in results):
                raise StepFailed("step deadline reached", "deadline")
            for call, result in zip(reply.tool_calls, results):
                lines.append("%s: %s" % (_bounded_line(_label(call.name)), _artifact_line(result)))
                messages.append(tool_message(call, result))
        raise StepFailed("round cap reached", "rounds")
    finally:
        doors.close()


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
            if self.server.driver == "scripted":
                reply = run_scripted(proxy_url, run_token, self.server.model, step["input"],
                                     self.server.scripted, call_model=self.server.call_model)
            elif self.server.driver == "llm":
                reply = run_llm(proxy_url, run_token, self.server.model, step["input"], self.server.llm)
            else:
                reply = self.server.call_model(proxy_url, run_token, self.server.model, step["input"])
        except StepFailed as exc:
            # The reason is fixed per leg: exception text can carry the proxy
            # URL, the token, or upstream error bodies, none of which belong
            # in a ledger. The class name is for the operator's log.
            self.log_message("%s: %s", exc.reason, exc.cause)
            self._json({"artifact": "", "success": False, "reason": exc.reason})
            return
        except Exception as exc:  # noqa: BLE001 — any failure is a failed step
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


def make_server(socket_path, addr, model, call_model=call_model, driver="model", scripted=None, llm=None):
    """Serve the step contract on socket_path (Unix) when given, else on addr
    (host:port), answering steps with the given driver."""
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
    srv.driver = driver
    srv.scripted = scripted
    srv.llm = llm
    return srv


def _at_least_one(value):
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return n


def _positive_seconds(value):
    s = float(value)
    if not s > 0:
        raise argparse.ArgumentTypeError("must be a positive number of seconds")
    return s


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="LangChain agent for Agenthof (one governed model call per step, every door in a fixed order, or a model choosing the doors)")
    # Single dash on purpose: the refbox recipe appends "-socket <path>" after
    # the image name, and the last -socket given wins.
    p.add_argument("-socket", dest="socket", default="", help="Unix socket path to listen on; overrides --addr")
    # Also single dash: the hermetic refspawn test stand-in's fake podman
    # appends "-workspace <dir>" after the image in place of the volume mount
    # (the shipped deploy/refspawn passes only "-socket <sock>" and mounts the
    # volume at /work). This agent keeps no files; the flag is accepted so the
    # launch succeeds either way.
    p.add_argument("-workspace", dest="workspace", default="", help="accepted and ignored: this agent keeps no files")
    p.add_argument("--addr", default="127.0.0.1:8082", help="TCP listen address when -socket is not set")
    p.add_argument("--model", default="fast", help="logical model name this agent is configured with")
    p.add_argument("--driver", choices=DRIVERS, default="model",
                   help="model: one governed model call per step (default); scripted: model, exec, two tool calls, parallel spawns, in that order; llm: a model offered the doors as tools decides which to call")
    p.add_argument("--exec-argv", default="env", help="scripted/llm: the allowlisted command to run through the exec door (space-separated)")
    p.add_argument("--obo-tool", default="whoami", help="scripted/llm: the tool to call on the on-behalf-of resource")
    p.add_argument("--bridge-tool", default="echo", help="scripted/llm: the tool to call on the bridged stdio resource (called with the step input as text)")
    p.add_argument("--spawn-role", default="acceptance-worker", help="scripted/llm: the role of the sub-agent runs")
    p.add_argument("--spawn-workflow", default="acceptance-sub", help="scripted/llm: the workflow of the sub-agent runs")
    p.add_argument("--spawns", type=_at_least_one, default=2, help="scripted/llm: how many sub-agent runs to start in parallel")
    p.add_argument("--max-rounds", type=_at_least_one, default=8, help="llm: the most model rounds one step may take before it fails")
    p.add_argument("--step-budget", type=_positive_seconds, default=240.0,
                   help="llm: seconds after which no further model or door call starts; set it below the engine's step_timeout")
    return p.parse_args(argv)


def scripted_from(opts):
    return Scripted(opts.exec_argv.split(), opts.obo_tool, opts.bridge_tool, opts.spawn_role, opts.spawn_workflow, opts.spawns)


def llm_from(opts):
    return Llm(scripted_from(opts), opts.max_rounds, opts.step_budget)


def main(argv=None):
    opts = parse_args(argv)
    srv = make_server(opts.socket, opts.addr, opts.model, driver=opts.driver, scripted=scripted_from(opts), llm=llm_from(opts))
    where = "unix:" + opts.socket if opts.socket else "%s:%d" % srv.server_address[:2]
    sys.stderr.write("langchain-agent listening on %s, logical model %s, driver %s\n" % (where, opts.model, opts.driver))
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
