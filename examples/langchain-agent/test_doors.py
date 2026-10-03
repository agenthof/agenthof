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
        self.server.should_exit = True
        self.thread.join(5)


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


if __name__ == "__main__":
    unittest.main()
