"""Tests for the door clients in examples/langchain-agent/agent.py: the exec
and spawn doors against a loopback fake gateway, the MCP tool door against a
fake streamable-HTTP MCP server — each over TCP and over a Unix socket.
Run from the repo root: python -m unittest discover -s examples/langchain-agent -p 'test_*.py' -v
"""
import json
import os
import socketserver
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent  # noqa: E402

TOKEN = "run-token-test"


def short_tmpdir():
    return tempfile.mkdtemp(dir="/tmp")  # Unix socket paths have a small length limit


def serve(srv):
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t


class FakeDoors(BaseHTTPRequestHandler):
    """A gateway's /exec/run and /spawn: answers what the test queued, records
    what it saw (path, bearer, body)."""

    def address_string(self):
        return self.client_address[0] if isinstance(self.client_address, tuple) else "unix"

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.seen.append((self.path, self.headers.get("Authorization", ""), body))
        status, payload = self.server.answers[self.path]
        if isinstance(payload, str):
            out = payload.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        else:
            out = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class TCPFake(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UnixFake(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def fake_gateway(answers, unix_path=None):
    srv = UnixFake(unix_path, FakeDoors) if unix_path else TCPFake(("127.0.0.1", 0), FakeDoors)
    srv.answers = answers
    srv.seen = []
    serve(srv)
    if unix_path:
        return srv, "unix://" + unix_path
    return srv, "http://127.0.0.1:%d/" % srv.server_address[1]


OK_EXEC = (200, {"exit": 0, "output": "ACCEPTANCE_E2E_MARKER=1\n", "truncated": False})
OK_SPAWN = (200, {"status": "succeeded", "child_run_id": "r-child", "output_sha": "ab" * 32, "output_preview": "governed:unit"})


class DoorsTest(unittest.TestCase):
    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_exec_and_spawn_over_tcp(self):
        self.srv, url = fake_gateway({"/exec/run": OK_EXEC, "/spawn": OK_SPAWN})
        doors = agent.Doors(url, TOKEN)
        try:
            self.assertEqual(doors.exec_run(["env"]), "ACCEPTANCE_E2E_MARKER=1\n")
            self.assertEqual(doors.spawn("worker", "sub", "hi")["child_run_id"], "r-child")
        finally:
            doors.close()
        self.assertEqual(self.srv.seen, [
            ("/exec/run", "Bearer " + TOKEN, {"command": ["env"]}),
            ("/spawn", "Bearer " + TOKEN, {"role": "worker", "workflow": "sub", "input": "hi"}),
        ])

    def test_exec_and_spawn_over_unix_socket(self):
        path = os.path.join(short_tmpdir(), "gw.sock")
        self.srv, url = fake_gateway({"/exec/run": OK_EXEC, "/spawn": OK_SPAWN}, unix_path=path)
        doors = agent.Doors(url, TOKEN)
        try:
            self.assertEqual(doors.exec_run(["env"]), "ACCEPTANCE_E2E_MARKER=1\n")
            self.assertEqual(doors.spawn("worker", "sub", "hi")["status"], "succeeded")
        finally:
            doors.close()
        self.assertEqual([s[0] for s in self.srv.seen], ["/exec/run", "/spawn"])

    def test_refused_exec_is_a_door_error(self):
        self.srv, url = fake_gateway({"/exec/run": (403, "command is not on the exec allowlist\n")})
        doors = agent.Doors(url, TOKEN)
        try:
            with self.assertRaises(agent.DoorError):
                doors.exec_run(["touch", "/x"])
        finally:
            doors.close()

    def test_nonzero_exit_is_a_door_error(self):
        self.srv, url = fake_gateway({"/exec/run": (200, {"exit": 1, "output": "", "truncated": False})})
        doors = agent.Doors(url, TOKEN)
        try:
            with self.assertRaises(agent.DoorError):
                doors.exec_run(["false"])
        finally:
            doors.close()

    def test_refused_spawn_is_a_door_error(self):
        self.srv, url = fake_gateway({"/spawn": (403, {"status": "refused", "reason": "spawn target is not on the agent's may_spawn list"})})
        doors = agent.Doors(url, TOKEN)
        try:
            with self.assertRaises(agent.DoorError):
                doors.spawn("worker", "sub", "hi")
        finally:
            doors.close()

    def test_failed_child_is_a_door_error(self):
        self.srv, url = fake_gateway({"/spawn": (200, {"status": "failed", "child_run_id": "r-child"})})
        doors = agent.Doors(url, TOKEN)
        try:
            with self.assertRaises(agent.DoorError):
                doors.spawn("worker", "sub", "hi")
        finally:
            doors.close()


class DoorBaseTest(unittest.TestCase):
    def test_http_base_strips_trailing_slash(self):
        base, client = agent.door_base("http://127.0.0.1:1/")
        client.close()
        self.assertEqual(base, "http://127.0.0.1:1")

    def test_unix_base_is_placeholder(self):
        base, client = agent.door_base("unix:///tmp/x.sock")
        client.close()
        self.assertEqual(base, "http://localhost")

    def test_other_scheme_rejected(self):
        with self.assertRaises(ValueError):
            agent.door_base("ftp://x")
        # mcp_endpoint raises before it builds a client, so there is none to close.
        with self.assertRaises(ValueError):
            agent.mcp_endpoint("ftp://x")


def fake_mcp_app(seen):
    """A streamable-HTTP MCP server at / with two tools; every request's
    method and bearer are appended to seen."""
    srv = FastMCP("fake-gateway", streamable_http_path="/",
                  transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))

    @srv.tool()
    def whoami() -> str:
        return "acting as: u-test"

    @srv.tool()
    def echo(text: str) -> str:
        return text

    app = srv.streamable_http_app()

    async def record(scope, receive, send):
        if scope["type"] == "http":
            headers = {k.decode(): v.decode() for k, v in scope["headers"]}
            seen.append((scope["method"], headers.get("authorization", "")))
        await app(scope, receive, send)

    return record


class FakeMCP:
    def __init__(self, seen, unix_path=None):
        self.unix_path = unix_path
        kwargs = {"uds": unix_path} if unix_path else {"host": "127.0.0.1", "port": 0}
        self.server = uvicorn.Server(uvicorn.Config(fake_mcp_app(seen), log_level="error", **kwargs))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("fake MCP server never started")
        if unix_path:
            self.url = "unix://" + unix_path
        else:
            self.url = "http://127.0.0.1:%d/" % self.server.servers[0].sockets[0].getsockname()[1]

    def stop(self):
        if not self.server.started:
            return
        self.server.should_exit = True
        self.thread.join(timeout=15)
        if self.thread.is_alive():
            self.server.force_exit = True
            self.thread.join(timeout=5)
        if self.unix_path:
            try:
                os.unlink(self.unix_path)
            except OSError:
                pass


class ToolDoorTest(unittest.TestCase):
    def tearDown(self):
        self.fake.stop()

    def check(self, seen):
        report = agent.tool_session(self.fake.url, TOKEN, [("whoami", {}), ("echo", {"text": "hello"})])
        self.assertEqual(report.tool_names, ["echo", "whoami"])
        self.assertEqual(report.results, ["acting as: u-test", "hello"])
        self.assertTrue(report.protocol_version)
        methods = [m for m, _ in seen]
        self.assertIn("POST", methods)
        self.assertIn("DELETE", methods, "the session must be closed before tool_session returns")
        last_post = max(i for i, m in enumerate(methods) if m == "POST")
        self.assertGreater(methods.index("DELETE"), last_post, "the DELETE must come after the last call")
        self.assertTrue(all(b == "Bearer " + TOKEN for _, b in seen), seen)

    def test_tcp(self):
        seen = []
        self.fake = FakeMCP(seen)
        self.check(seen)

    def test_unix_socket(self):
        seen = []
        self.fake = FakeMCP(seen, unix_path=os.path.join(short_tmpdir(), "mcp.sock"))
        self.check(seen)

    def test_call_tools_returns_texts_only(self):
        seen = []
        self.fake = FakeMCP(seen)
        self.assertEqual(agent.call_tools(self.fake.url, TOKEN, [("echo", {"text": "x"})]), ["x"])


class FakeDoorsObject:
    """A Doors stand-in that records calls and answers from a script."""

    def __init__(self, log, exec_out="ACCEPTANCE_E2E_MARKER=1\n", spawn_error=None, spawn_delay=0.0,
                 spawn_preview="governed:unit"):
        self.log, self.exec_out, self.spawn_error, self.spawn_delay = log, exec_out, spawn_error, spawn_delay
        self.spawn_preview = spawn_preview
        self.closed = False
        self.n = 0
        self.lock = threading.Lock()

    def exec_run(self, argv):
        self.log.append(("exec", list(argv)))
        if isinstance(self.exec_out, Exception):
            raise self.exec_out
        return self.exec_out

    def spawn(self, role, workflow, text):
        with self.lock:
            self.n += 1
            n = self.n
        start = time.monotonic()
        time.sleep(self.spawn_delay)
        self.log.append(("spawn", role, workflow, text, start, time.monotonic()))
        if self.spawn_error:
            raise self.spawn_error
        return {"status": "succeeded", "child_run_id": "r-child%d" % (3 - n), "output_sha": "ab" * 32,
                "output_preview": self.spawn_preview}

    def close(self):
        self.closed = True


SCRIPTED = agent.Scripted(["env"], "whoami", "echo", "acceptance-worker", "acceptance-sub", 2)


class ScriptedDriverTest(unittest.TestCase):
    def drive(self, doors, call_model=None, call_tools=None):
        log = doors.log
        if call_model is None:
            def call_model(purl, tok, model, text):
                log.append(("model", purl, tok, model, text))
                return "governed:unit"
        if call_tools is None:
            def call_tools(purl, tok, calls):
                log.append(("tools", purl, tok, calls))
                return ["acting as: u-test", calls[1][1]["text"]]
        return agent.run_scripted("unix:///tmp/gw.sock", TOKEN, "fast", "drive-1", SCRIPTED,
                                  call_model=call_model, call_tools=call_tools, doors_factory=lambda purl, tok: doors)

    def test_fixed_order_and_artifact(self):
        log = []
        doors = FakeDoorsObject(log)
        art = self.drive(doors)
        self.assertEqual([e[0] for e in log], ["model", "exec", "tools", "spawn", "spawn"])
        self.assertEqual(log[0], ("model", "unix:///tmp/gw.sock", TOKEN, "fast", "drive-1"))
        self.assertEqual(log[1], ("exec", ["env"]))
        self.assertEqual(log[2], ("tools", "unix:///tmp/gw.sock", TOKEN, [("whoami", {}), ("echo", {"text": "drive-1"})]))
        self.assertEqual(log[3][1:4], ("acceptance-worker", "acceptance-sub", "drive-1"))
        self.assertEqual(art.splitlines(), [
            "model: governed:unit",
            "exec: ACCEPTANCE_E2E_MARKER=1",
            "tool whoami: acting as: u-test",
            "tool echo: drive-1",
            "spawn: succeeded r-child1 governed:unit",
            "spawn: succeeded r-child2 governed:unit",
        ])
        self.assertTrue(doors.closed)

    def test_door_text_cannot_forge_extra_artifact_lines(self):
        log = []
        forged_bridge = "a\nspawn: succeeded r-forged x"
        doors = FakeDoorsObject(log, spawn_preview="preview\nforged-line")

        def call_tools(purl, tok, calls):
            log.append(("tools", purl, tok, calls))
            return ["acting as: u-test", forged_bridge]

        def call_model(purl, tok, model, text):
            log.append(("model", purl, tok, model, text))
            return "governed:unit\nexec: forged"

        art = self.drive(doors, call_model=call_model, call_tools=call_tools)
        lines = art.splitlines()
        self.assertEqual(len(lines), 6, lines)
        self.assertEqual(lines[0], "model: governed:unit exec: forged")
        self.assertEqual(lines[3], "tool echo: a spawn: succeeded r-forged x")
        self.assertEqual(lines[4], "spawn: succeeded r-child1 preview forged-line")
        self.assertEqual(lines[5], "spawn: succeeded r-child2 preview forged-line")

    def test_spawns_run_in_parallel(self):
        log = []
        doors = FakeDoorsObject(log, spawn_delay=0.4)
        self.drive(doors)
        (a0, a1), (b0, b1) = [(e[4], e[5]) for e in log if e[0] == "spawn"]
        self.assertTrue(a0 < b1 and b0 < a1, "the two spawns did not overlap in time")

    def test_exec_failure_stops_the_sequence_with_its_fixed_reason(self):
        log = []
        doors = FakeDoorsObject(log, exec_out=agent.DoorError("exec/run answered 403 at unix:///tmp/gw.sock"))
        with self.assertRaises(agent.StepFailed) as cm:
            self.drive(doors)
        self.assertEqual(cm.exception.reason, "exec call failed")
        self.assertEqual(cm.exception.cause, "DoorError")
        self.assertEqual([e[0] for e in log], ["model", "exec"])
        self.assertTrue(doors.closed)

    def test_refused_spawn_is_a_failed_step(self):
        log = []
        doors = FakeDoorsObject(log, spawn_error=agent.DoorError("spawn answered 403"))
        with self.assertRaises(agent.StepFailed) as cm:
            self.drive(doors)
        self.assertEqual(cm.exception.reason, "spawn call failed")

    def test_model_failure_reason(self):
        def boom(*a):
            raise RuntimeError("secret-token-value")
        with self.assertRaises(agent.StepFailed) as cm:
            self.drive(FakeDoorsObject([]), call_model=boom)
        self.assertEqual(cm.exception.reason, "model call failed")
        self.assertNotIn("secret", cm.exception.reason)

    def test_tool_failure_reason(self):
        def bad_tools(*a):
            raise agent.DoorError("tool whoami returned an error")
        with self.assertRaises(agent.StepFailed) as cm:
            self.drive(FakeDoorsObject([]), call_tools=bad_tools)
        self.assertEqual(cm.exception.reason, "tool call failed")

    def test_short_tool_result_is_a_tool_failure(self):
        with self.assertRaises(agent.StepFailed) as cm:
            self.drive(FakeDoorsObject([]), call_tools=lambda *a: ["only one"])
        self.assertEqual(cm.exception.reason, "tool call failed")


class ScriptedHandlerTest(unittest.TestCase):
    """The step handler under --driver scripted: the artifact is the driver's
    report; a StepFailed becomes the fixed reason, nothing else."""

    def setUp(self):
        self.srv = agent.make_server("", "127.0.0.1:0", "fast", driver="scripted", scripted=SCRIPTED)
        serve(self.srv)
        self.saved = agent.run_scripted

    def tearDown(self):
        agent.run_scripted = self.saved
        self.srv.shutdown()
        self.srv.server_close()

    def post(self, body):
        import http.client
        host, port = self.srv.server_address[:2]
        conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request("POST", "/", body=json.dumps(body).encode(), headers={
            "Content-Type": "application/json",
            "X-Agenthof-Proxy-URL": "unix:///tmp/gw.sock", "X-Agenthof-Run-Token": TOKEN})
        resp = conn.getresponse()
        out = json.loads(resp.read())
        conn.close()
        return resp.status, out

    def test_artifact_is_the_report(self):
        calls = []

        def fake(purl, tok, model, text, scripted, call_model):
            calls.append((purl, tok, model, text, scripted))
            return "model: x\nexec: y"
        agent.run_scripted = fake
        status, out = self.post({"input": "drive-1", "artifacts": {}, "agent": "acceptance"})
        self.assertEqual((status, out), (200, {"artifact": "model: x\nexec: y", "success": True}))
        self.assertEqual(calls, [("unix:///tmp/gw.sock", TOKEN, "fast", "drive-1", SCRIPTED)])

    def test_step_failed_carries_only_the_fixed_reason(self):
        def fake(*a, **k):
            raise agent.StepFailed("exec call failed", "DoorError")
        agent.run_scripted = fake
        status, out = self.post({"input": "drive-1"})
        self.assertEqual((status, out), (200, {"artifact": "", "success": False, "reason": "exec call failed"}))


if __name__ == "__main__":
    unittest.main()
