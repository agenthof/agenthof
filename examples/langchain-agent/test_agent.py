"""Tests for examples/langchain-agent/agent.py.
Run from the repo root: python -m unittest discover -s examples/langchain-agent -p 'test_*.py' -v
Needs the pinned dependencies installed (pip install -r examples/langchain-agent/requirements.txt).
"""
import http.client
import json
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PROVIDER = REPO / "scripts" / "fake-openai-provider.py"
sys.path.insert(0, str(HERE))
import agent  # noqa: E402

GATEWAY = {"X-Agenthof-Proxy-URL": "unix:///tmp/gw.sock", "X-Agenthof-Run-Token": "run-token-test"}


def serve(srv):
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t


def tcp_conn(srv):
    host, port = srv.server_address[:2]
    return http.client.HTTPConnection(host, port, timeout=10)


def unix_conn(path):
    conn = http.client.HTTPConnection("localhost", timeout=10)
    conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.sock.connect(path)
    return conn


def post(conn, body=None, headers=None, raw=None):
    data = raw if raw is not None else json.dumps(body).encode()
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers or {})
    conn.request("POST", "/", body=data, headers=hdrs)
    resp = conn.getresponse()
    out = resp.read()
    conn.close()
    return resp.status, out


def short_tmpdir():
    return tempfile.mkdtemp(dir="/tmp")  # Unix socket paths have a small length limit


def start_provider(*args):
    proc = subprocess.Popen([sys.executable, str(PROVIDER), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    listening = json.loads(proc.stdout.readline())["listening"]
    proc.stdout.close()  # the provider prints nothing more; avoids an unclosed-file warning
    return proc, listening


class GatewayClientTest(unittest.TestCase):
    def test_unix_scheme_dials_the_socket(self):
        path = os.path.join(short_tmpdir(), "gw.sock")

        class Ping(BaseHTTPRequestHandler):
            def address_string(self):
                return "unix"

            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "4")
                self.end_headers()
                self.wfile.write(b"pong")

        srv = socketserver.UnixStreamServer(path, Ping)
        serve(srv)
        try:
            base_url, client = agent.gateway_client("unix://" + path)
            self.assertEqual(base_url, "http://localhost/v1")
            self.assertIsNotNone(client)
            resp = client.get("http://localhost/ping")
            client.close()
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, "pong")

    def test_http_scheme_strips_trailing_slash(self):
        base_url, client = agent.gateway_client("http://127.0.0.1:1/")
        self.assertEqual(base_url, "http://127.0.0.1:1/v1")
        self.assertNotIn("//v1", base_url)
        self.assertIsNone(client)

    def test_http_scheme_without_slash(self):
        base_url, _ = agent.gateway_client("http://127.0.0.1:1")
        self.assertEqual(base_url, "http://127.0.0.1:1/v1")

    def test_other_scheme_rejected(self):
        with self.assertRaises(ValueError):
            agent.gateway_client("ftp://127.0.0.1/x")


class HandlerTest(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def fake(proxy_url, run_token, model, text):
            self.calls.append((proxy_url, run_token, model, text))
            return "reply:" + text

        self.srv = agent.make_server("", "127.0.0.1:0", "fast", call_model=fake)
        serve(self.srv)

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_valid_step_returns_artifact(self):
        status, out = post(tcp_conn(self.srv), {"input": "hello", "artifacts": {}, "agent": "lc"}, GATEWAY)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(out), {"artifact": "reply:hello", "success": True})
        self.assertEqual(self.calls, [("unix:///tmp/gw.sock", "run-token-test", "fast", "hello")])

    def test_non_json_body_is_400(self):
        status, _ = post(tcp_conn(self.srv), raw=b"not json", headers=GATEWAY)
        self.assertEqual(status, 400)
        self.assertEqual(self.calls, [])

    def test_json_list_body_is_400(self):
        status, _ = post(tcp_conn(self.srv), [1, 2, 3], GATEWAY)
        self.assertEqual(status, 400)

    def test_input_not_a_string_is_400(self):
        status, _ = post(tcp_conn(self.srv), {"input": 5}, GATEWAY)
        self.assertEqual(status, 400)

    def test_bad_content_length_is_400(self):
        conn = tcp_conn(self.srv)
        conn.putrequest("POST", "/")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", "abc")
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 400)

    def test_oversized_body_is_413(self):
        conn = tcp_conn(self.srv)
        conn.putrequest("POST", "/")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str((1 << 20) + 1))
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 413)

    def test_missing_gateway_headers_is_failed_step(self):
        status, out = post(tcp_conn(self.srv), {"input": "hello"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(out), {"artifact": "", "success": False, "reason": "model proxy coordinates missing"})
        self.assertEqual(self.calls, [])

    def test_model_failure_is_fixed_reason(self):
        def boom(*a):
            raise RuntimeError("upstream said: secret-token-value at unix:///tmp/gw.sock")

        self.srv.call_model = boom
        status, out = post(tcp_conn(self.srv), {"input": "hello"}, GATEWAY)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(out), {"artifact": "", "success": False, "reason": "model call failed"})
        self.assertNotIn(b"secret", out)
        self.assertNotIn(b"gw.sock", out)

    def test_get_is_405(self):
        conn = tcp_conn(self.srv)
        conn.request("GET", "/")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 405)


class UnixServeTest(unittest.TestCase):
    def test_serves_the_contract_on_a_unix_socket_and_unlinks_on_close(self):
        path = os.path.join(short_tmpdir(), "agent.sock")
        with open(path, "w") as f:  # a stale file from a killed process must not block the bind
            f.write("stale")
        srv = agent.make_server(path, "", "fast", call_model=lambda *a: "ok")
        serve(srv)
        try:
            status, out = post(unix_conn(path), {"input": "x"}, GATEWAY)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(out), {"artifact": "ok", "success": True})
        self.assertFalse(os.path.exists(path))


class RealModelCallTest(unittest.TestCase):
    """Drives the real langchain-openai chain over a Unix socket. The provider
    stands in for the gateway: what it logs is what the SDK put on the wire."""

    def setUp(self):
        self.dir = short_tmpdir()
        self.sock = os.path.join(self.dir, "gw.sock")
        self.log = os.path.join(self.dir, "provider.jsonl")

    def tearDown(self):
        self.proc.kill()
        self.proc.wait()

    def test_call_targets_chat_completions_with_the_bearer(self):
        self.proc, _ = start_provider("--unix", self.sock, "--reply", "governed:unit", "--log", self.log)
        reply = agent.call_model("unix://" + self.sock, "run-token-test", "fast", "hello")
        self.assertEqual(reply, "governed:unit")
        with open(self.log, encoding="utf-8") as f:
            lines = [json.loads(line) for line in f]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["path"], "/v1/chat/completions")
        self.assertEqual(lines[0]["authorization"], "Bearer run-token-test")
        self.assertEqual(lines[0]["model"], "fast")
        self.assertEqual(lines[0]["messages"][0]["content"], "hello")
        self.assertFalse([h for h in lines[0]["headers"] if h.startswith("x-agenthof")])

    def test_refusal_becomes_failed_step(self):
        self.proc, _ = start_provider("--unix", self.sock, "--status", "403")
        srv = agent.make_server("", "127.0.0.1:0", "fast")  # the real call_model
        serve(srv)
        try:
            status, out = post(tcp_conn(srv), {"input": "hello"},
                               {"X-Agenthof-Proxy-URL": "unix://" + self.sock, "X-Agenthof-Run-Token": "run-token-test"})
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(out), {"artifact": "", "success": False, "reason": "model call failed"})


class ArgsTest(unittest.TestCase):
    def test_single_dash_socket(self):
        opts = agent.parse_args(["-socket", "/run/agenthof/a.sock"])
        self.assertEqual(opts.socket, "/run/agenthof/a.sock")

    def test_last_socket_wins(self):
        # The image ENTRYPOINT carries one -socket and the refbox recipe appends another.
        opts = agent.parse_args(["-socket", "/run/agenthof/a.sock", "-socket", "/tmp/x/b.sock"])
        self.assertEqual(opts.socket, "/tmp/x/b.sock")

    def test_defaults(self):
        opts = agent.parse_args([])
        self.assertEqual((opts.socket, opts.addr, opts.model), ("", "127.0.0.1:8082", "fast"))


class RequirementsTest(unittest.TestCase):
    def test_every_requirement_is_pinned(self):
        lines = [l.strip() for l in (HERE / "requirements.txt").read_text().splitlines()]
        reqs = [l for l in lines if l and not l.startswith("#")]
        self.assertTrue(reqs)
        for req in reqs:
            self.assertIn("==", req, req)


if __name__ == "__main__":
    unittest.main()
