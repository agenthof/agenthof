"""Tests for scripts/fake-openai-provider.py (run: python -m unittest discover -s scripts -p 'test_*.py')."""
import http.client
import json
import os
import re
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


class ReplyForTest(unittest.TestCase):
    def test_per_model_reply_overrides_default(self):
        # --reply-for answers a call by the request's model; an unmapped model
        # falls back to --reply. This is what lets one provider serve both the
        # router (classifier) and the chat (answer) legs of an ask run.
        proc, listening = start(
            "--bind", "127.0.0.1:0", "--reply", "answered:nonce", "--reply-for", "router=1",
        )
        try:
            def content(model):
                status, data = post(tcp_conn(listening), "/v1/chat/completions",
                                    {"model": model, "messages": [{"role": "user", "content": "hi"}]},
                                    {"Authorization": "Bearer k"})
                self.assertEqual(status, 200)
                return json.loads(data)["choices"][0]["message"]["content"]
            self.assertEqual(content("router"), "1")
            self.assertEqual(content("chat"), "answered:nonce")
        finally:
            proc.kill()
            proc.wait()

    def test_malformed_reply_for_is_rejected(self):
        proc = subprocess.Popen(
            [sys.executable, str(PROVIDER), "--bind", "127.0.0.1:0", "--reply-for", "no-equals-sign"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        _, err = proc.communicate(timeout=5)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("MODEL=TEXT", err)


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


class EmbeddingsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "provider.jsonl")
        self.proc, self.listening = start("--bind", "127.0.0.1:0", "--log", self.log)

    def tearDown(self):
        self.proc.kill()
        self.proc.wait()
        self.tmp.cleanup()

    def embed(self, text):
        status, data = post(tcp_conn(self.listening), "/v1/embeddings",
                            {"model": "embed", "input": text}, {"Authorization": "Bearer k"})
        self.assertEqual(status, 200)
        return data, json.loads(data)["data"][0]["embedding"]

    def test_deterministic_fixed_dimension_and_distinguishable(self):
        a1_raw, a1 = self.embed("the entitlement is granted to a named agent")
        a2_raw, a2 = self.embed("the entitlement is granted to a named agent")
        self.assertEqual(a1_raw, a2_raw)  # byte-identical response
        self.assertEqual(a1, a2)
        _, b = self.embed("catering for the autumn offsite")
        self.assertEqual(len(a1), len(b))
        self.assertEqual(len(a1), 512)
        self.assertNotEqual(a1, b)

    def test_retrieval_selects_the_matching_text(self):
        def dot(x, y):
            return sum(p * q for p, q in zip(x, y))
        _, query = self.embed("how is an entitlement granted to an agent")
        _, near = self.embed("an entitlement is granted to a named agent")
        _, far = self.embed("the caterer offers vegetarian lunch at the offsite")
        self.assertGreater(dot(query, near), dot(query, far))

    def sample_notes(self):
        """The real sample note bodies, read from the fake-drive source."""
        src = (Path(__file__).resolve().parent.parent / "examples" / "fake-drive-mcp" / "main.go").read_text(encoding="utf-8")
        found = dict(re.findall(r"const (\w+Note) = `(.*?)`", src, re.S))
        self.assertEqual(sorted(found), ["entitlementsNote", "offsiteNote", "tokenNote"])
        return found

    def test_queries_select_the_right_sample_note_by_margin(self):
        # The grounding proof depends on retrieval picking the right note, so
        # prove it on the real notes (whole, and per chunk) with a clear gap.
        def dot(x, y):
            return sum(p * q for p, q in zip(x, y))
        notes = self.sample_notes()
        whole = {name: self.embed(body)[1] for name, body in notes.items()}
        chunks = [(name, self.embed(c)[1]) for name, body in notes.items() for c in body.split("\n\n")]
        margin = 0.10
        cases = {
            "entitlementsNote": ["how is an entitlement granted to an agent", "entitlement revocation",
                                 "what entitlements does an agent have"],
            "tokenNote": ["JWT verification", "token handling", "how long do access tokens live"],
        }
        for want, queries in cases.items():
            for q in queries:
                qv = self.embed(q)[1]
                scored = sorted(((dot(qv, v), n) for n, v in whole.items()), reverse=True)
                self.assertEqual(scored[0][1], want, (q, scored))
                self.assertGreaterEqual(scored[0][0] - scored[1][0], margin, (q, scored))
                best = sorted(((dot(qv, v), n) for n, v in chunks), reverse=True)
                self.assertEqual(best[0][1], want, (q, best[:3]))
                other = max(s for s, n in best if n != want)
                self.assertGreaterEqual(best[0][0] - other, margin, (q, best[:3]))

    def test_request_is_logged_with_the_input_text(self):
        self.embed("secret grounding text")
        post(tcp_conn(self.listening), "/v1/embeddings",
             {"model": "embed", "input": ["one", "two"]}, {"Authorization": "Bearer k"})
        with open(self.log, encoding="utf-8") as f:
            lines = [json.loads(line) for line in f]
        self.assertEqual(lines[0]["path"], "/v1/embeddings")
        self.assertEqual(lines[0]["input"], "secret grounding text")
        self.assertEqual(lines[1]["input"], ["one", "two"])

    def test_batch_input_and_bad_input(self):
        status, data = post(tcp_conn(self.listening), "/v1/embeddings",
                            {"input": ["one", "two"]}, {"Authorization": "Bearer k"})
        self.assertEqual(status, 200)
        self.assertEqual([d["index"] for d in json.loads(data)["data"]], [0, 1])
        status, _ = post(tcp_conn(self.listening), "/v1/embeddings", {"input": 5}, {"Authorization": "Bearer k"})
        self.assertEqual(status, 400)
        status, _ = post(tcp_conn(self.listening), "/v1/embeddings", {"input": "x"}, {})
        self.assertEqual(status, 401)


EXEC_TOOL = {"type": "function", "function": {"name": "exec", "description": "run", "parameters": {"type": "object"}}}
ECHO_TOOL = {"type": "function", "function": {"name": "echo", "description": "echo", "parameters": {"type": "object"}}}
SCRIPT = {"rounds": [
    [{"name": "exec", "arguments": {"command": ["env"]}}],
    [{"name": "echo", "arguments": {"text": "drive-1"}}, {"name": "whoami", "arguments": {}}],
]}


def assistant_round(r, names):
    return {"role": "assistant", "content": None, "tool_calls": [
        {"id": "call_%d_%d" % (r, i), "type": "function", "function": {"name": n, "arguments": "{}"}}
        for i, n in enumerate(names)]}


def tool_results(r, n):
    return [{"role": "tool", "tool_call_id": "call_%d_%d" % (r, i), "content": "ok"} for i in range(n)]


class ToolScriptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "provider.jsonl")
        self.script = os.path.join(self.tmp.name, "script.json")
        with open(self.script, "w", encoding="utf-8") as f:
            json.dump(SCRIPT, f)
        self.proc, self.listening = start("--bind", "127.0.0.1:0", "--reply", "final:xyz", "--log", self.log,
                                          "--tool-script", self.script)

    def tearDown(self):
        self.proc.kill()
        self.proc.wait()
        self.tmp.cleanup()

    def chat(self, messages, tools=None):
        body = {"model": "fast", "messages": messages}
        if tools is not None:
            body["tools"] = tools
        status, data = post(tcp_conn(self.listening), "/v1/chat/completions", body, {"Authorization": "Bearer host-key"})
        self.assertEqual(status, 200)
        return json.loads(data)["choices"][0]

    def log_lines(self):
        with open(self.log, encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    def test_first_round_is_keyed_by_zero_prior_tool_rounds(self):
        choice = self.chat([{"role": "user", "content": "go"}], tools=[EXEC_TOOL, ECHO_TOOL])
        self.assertEqual(choice["finish_reason"], "tool_calls")
        self.assertIsNone(choice["message"]["content"])
        calls = choice["message"]["tool_calls"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["id"], "call_0_0")
        self.assertEqual(calls[0]["type"], "function")
        self.assertEqual(calls[0]["function"]["name"], "exec")
        self.assertIsInstance(calls[0]["function"]["arguments"], str)
        self.assertEqual(json.loads(calls[0]["function"]["arguments"]), {"command": ["env"]})

    def test_second_round_is_keyed_by_one_prior_tool_round(self):
        messages = [{"role": "user", "content": "go"}, assistant_round(0, ["exec"]), *tool_results(0, 1)]
        choice = self.chat(messages, tools=[EXEC_TOOL, ECHO_TOOL])
        names = [c["function"]["name"] for c in choice["message"]["tool_calls"]]
        self.assertEqual(names, ["echo", "whoami"])
        self.assertEqual([c["id"] for c in choice["message"]["tool_calls"]], ["call_1_0", "call_1_1"])

    def test_exhausted_script_is_the_final_reply(self):
        messages = [{"role": "user", "content": "go"}, assistant_round(0, ["exec"]), *tool_results(0, 1),
                    assistant_round(1, ["echo", "whoami"]), *tool_results(1, 2)]
        choice = self.chat(messages, tools=[EXEC_TOOL, ECHO_TOOL])
        self.assertEqual(choice["finish_reason"], "stop")
        self.assertEqual(choice["message"]["content"], "final:xyz")
        self.assertNotIn("tool_calls", choice["message"])

    def test_request_without_tools_is_the_plain_reply(self):
        choice = self.chat([{"role": "user", "content": "child"}])
        self.assertEqual(choice["message"]["content"], "final:xyz")
        self.assertEqual(choice["finish_reason"], "stop")

    def test_log_records_tool_names_and_round(self):
        self.chat([{"role": "user", "content": "child"}])
        self.chat([{"role": "user", "content": "go"}, assistant_round(0, ["exec"]), *tool_results(0, 1)], tools=[EXEC_TOOL, ECHO_TOOL])
        lines = self.log_lines()
        self.assertEqual((lines[0]["tools"], lines[0]["tool_rounds"]), ([], 0))
        self.assertEqual((lines[1]["tools"], lines[1]["tool_rounds"]), (["exec", "echo"], 1))
        self.assertEqual(lines[1]["messages"][-1]["role"], "tool")


class ToolScriptValidationTest(unittest.TestCase):
    def test_malformed_script_is_refused_at_start(self):
        tmp = tempfile.TemporaryDirectory()
        path = os.path.join(tmp.name, "bad.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"rounds": [[{"name": "exec"}]]}, f)  # no arguments
        proc = subprocess.run([sys.executable, str(PROVIDER), "--bind", "127.0.0.1:0", "--tool-script", path],
                              capture_output=True, text=True, timeout=20)
        tmp.cleanup()
        self.assertEqual(proc.returncode, 2)
        self.assertIn("fake-provider: --tool-script", proc.stderr)


class DelayTest(unittest.TestCase):
    def test_delay_holds_the_answer(self):
        import time
        proc, listening = start("--bind", "127.0.0.1:0", "--delay", "1.5")
        try:
            t0 = time.monotonic()
            status, data = post(tcp_conn(listening), "/v1/chat/completions", CHAT, {"Authorization": "Bearer k"})
            held = time.monotonic() - t0
        finally:
            proc.kill()
            proc.wait()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["choices"][0]["message"]["content"], "fake reply")
        self.assertGreaterEqual(held, 1.5)

    def test_no_delay_by_default(self):
        import time
        proc, listening = start("--bind", "127.0.0.1:0")
        try:
            t0 = time.monotonic()
            status, _ = post(tcp_conn(listening), "/v1/chat/completions", CHAT, {"Authorization": "Bearer k"})
            held = time.monotonic() - t0
        finally:
            proc.kill()
            proc.wait()
        self.assertEqual(status, 200)
        self.assertLess(held, 1.0)

    def test_a_refused_call_is_not_delayed(self):
        import time
        proc, listening = start("--bind", "127.0.0.1:0", "--delay", "2")
        try:
            t0 = time.monotonic()
            status, _ = post(tcp_conn(listening), "/v1/chat/completions", CHAT, {})
            held = time.monotonic() - t0
        finally:
            proc.kill()
            proc.wait()
        self.assertEqual(status, 401)
        self.assertLess(held, 1.0)


if __name__ == "__main__":
    unittest.main()
