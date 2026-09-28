"""Tests for scripts/fake-openai-provider.py (run: python -m unittest discover -s scripts -p 'test_*.py')."""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROVIDER = Path(__file__).resolve().with_name("fake-openai-provider.py")


def start(*args):
    """Launch the provider; return (process, listening-address) once it has bound."""
    proc = subprocess.Popen(
        [sys.executable, str(PROVIDER), *args],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    listening = json.loads(proc.stdout.readline())["listening"]
    proc.stdout.close()  # the provider prints nothing more; avoids an unclosed-file warning
    return proc, listening


def tcp_conn(listening):
    host, _, port = listening.rpartition(":")
    return http.client.HTTPConnection(host, int(port), timeout=5)


def unix_conn(path):
    conn = http.client.HTTPConnection("localhost", timeout=5)
    conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.sock.connect(path)
    return conn


def post(conn, path, body, headers):
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers)
    conn.request("POST", path, body=json.dumps(body), headers=hdrs)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


CHAT = {"model": "fast", "messages": [{"role": "user", "content": "hi"}]}


class FakeProviderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "provider.jsonl")
        self.proc, self.listening = start("--bind", "127.0.0.1:0", "--reply", "governed:xyz", "--log", self.log)

    def tearDown(self):
        self.proc.kill()
        self.proc.wait()
        self.tmp.cleanup()

    def log_lines(self):
        with open(self.log, encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    def test_chat_completion_shape_and_log(self):
        status, data = post(tcp_conn(self.listening), "/v1/chat/completions", CHAT, {"Authorization": "Bearer host-key"})
        self.assertEqual(status, 200)
        body = json.loads(data)
        self.assertEqual(body["object"], "chat.completion")
        self.assertEqual(body["choices"][0]["message"]["content"], "governed:xyz")
        self.assertEqual(body["usage"], {"prompt_tokens": 3, "completion_tokens": 5, "total_tokens": 8})
        lines = self.log_lines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["path"], "/v1/chat/completions")
        self.assertEqual(lines[0]["authorization"], "Bearer host-key")
        self.assertEqual(lines[0]["model"], "fast")
        self.assertEqual(lines[0]["messages"], CHAT["messages"])
        self.assertIn("authorization", lines[0]["headers"])
        self.assertEqual(lines[0]["headers"], sorted(lines[0]["headers"]))

    def test_missing_bearer_is_401_and_still_logged(self):
        status, _ = post(tcp_conn(self.listening), "/v1/chat/completions", CHAT, {})
        self.assertEqual(status, 401)
        self.assertEqual(len(self.log_lines()), 1)

    def test_other_route_is_404_and_not_logged(self):
        status, _ = post(tcp_conn(self.listening), "/v1/responses", CHAT, {"Authorization": "Bearer host-key"})
        self.assertEqual(status, 404)
        self.assertFalse(os.path.exists(self.log))

    def test_non_json_body_is_400(self):
        conn = tcp_conn(self.listening)
        conn.request("POST", "/v1/chat/completions", body=b"not json",
                     headers={"Content-Type": "application/json", "Authorization": "Bearer host-key"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 400)


class StatusOverrideTest(unittest.TestCase):
    def test_status_override_refuses(self):
        proc, listening = start("--bind", "127.0.0.1:0", "--status", "403")
        try:
            status, data = post(tcp_conn(listening), "/v1/chat/completions", CHAT, {"Authorization": "Bearer k"})
        finally:
            proc.kill()
            proc.wait()
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(data), {"error": {"message": "fake provider refused"}})


class UnixListenerTest(unittest.TestCase):
    def test_serves_on_a_unix_socket(self):
        tmp = tempfile.mkdtemp(dir="/tmp")  # short: Unix socket paths have a small length limit
        path = os.path.join(tmp, "p.sock")
        proc, listening = start("--unix", path, "--reply", "over-uds")
        try:
            self.assertEqual(listening, "unix:" + path)
            status, data = post(unix_conn(path), "/v1/chat/completions", CHAT, {"Authorization": "Bearer k"})
        finally:
            proc.kill()
            proc.wait()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["choices"][0]["message"]["content"], "over-uds")


if __name__ == "__main__":
    unittest.main()
