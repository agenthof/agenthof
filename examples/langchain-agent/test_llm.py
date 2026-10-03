"""Tests for the llm driver in examples/langchain-agent/agent.py: the neutral
door-tool specs, the LangChain model shell over a Unix socket, and run_llm
driven by a fake tool-calling model with the door clients injected.
Run from the repo root: python -m unittest discover -s examples/langchain-agent -p 'test_*.py' -v
"""
import contextlib
import http.client
import io
import json
import os
import subprocess
import sys
import socketserver
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent  # noqa: E402
from test_doors import serve, short_tmpdir  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
PROVIDER = REPO / "scripts" / "fake-openai-provider.py"

TOKEN = "run-token-test"
WHOAMI = agent.ToolSpec("whoami", "who the upstream sees", {"type": "object", "properties": {}})
ECHO = agent.ToolSpec("echo", "echo text", {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]})


class ToolSpecTest(unittest.TestCase):
    def test_door_tools_are_the_two_doors_plus_the_discovered_set(self):
        specs = agent.door_tools([WHOAMI, ECHO])
        self.assertEqual([s.name for s in specs], ["exec", "spawn", "whoami", "echo"])
        self.assertEqual(specs[0], agent.EXEC_TOOL)
        self.assertEqual(specs[1], agent.SPAWN_TOOL)

    def test_exec_schema_is_an_argv_array(self):
        p = agent.EXEC_TOOL.parameters
        self.assertEqual(p["type"], "object")
        self.assertEqual(p["properties"]["command"]["type"], "array")
        self.assertEqual(p["properties"]["command"]["items"], {"type": "string"})
        self.assertEqual(p["required"], ["command"])
        self.assertTrue(agent.EXEC_TOOL.description)

    def test_spawn_schema_names_role_workflow_input(self):
        p = agent.SPAWN_TOOL.parameters
        self.assertEqual(sorted(p["properties"]), ["input", "role", "workflow"])
        self.assertEqual(sorted(p["required"]), ["input", "role", "workflow"])
        for prop in p["properties"].values():
            self.assertEqual(prop["type"], "string")

    def test_openai_tools_shape(self):
        tools = agent.openai_tools([agent.EXEC_TOOL, ECHO])
        self.assertEqual([t["type"] for t in tools], ["function", "function"])
        self.assertEqual(tools[0]["function"]["name"], "exec")
        self.assertEqual(tools[1]["function"], {"name": "echo", "description": "echo text", "parameters": ECHO.parameters})
        json.dumps(tools)  # must be plain JSON

    def test_collision_with_a_door_tool_fails_closed(self):
        for name in agent.DOOR_TOOL_NAMES:
            with self.assertRaises(agent.StepFailed) as cm:
                agent.door_tools([agent.ToolSpec(name, "an upstream tool with a door's name", {"type": "object"})])
            self.assertEqual(cm.exception.reason, "tool set conflict")


class MakeLLMTest(unittest.TestCase):
    def test_timeout_is_configurable_and_defaults_to_request_timeout(self):
        llm = agent.make_llm("http://127.0.0.1:1/", TOKEN, "fast")
        self.assertEqual(llm.request_timeout, agent.REQUEST_TIMEOUT)
        llm = agent.make_llm("http://127.0.0.1:1/", TOKEN, "fast", timeout=7)
        self.assertEqual(llm.request_timeout, 7)


def start_provider(*args):
    proc = subprocess.Popen([sys.executable, str(PROVIDER), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    listening = json.loads(proc.stdout.readline())["listening"]
    proc.stdout.close()
    return proc, listening


def write_script(directory, rounds):
    path = os.path.join(directory, "script.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"rounds": rounds}, f)
    return path


class RealBindToolsWireTest(unittest.TestCase):
    """The real ChatOpenAI.bind_tools over a Unix socket against the fake
    tool-calling provider: what the SDK puts on the wire, and what it parses."""

    def setUp(self):
        self.dir = short_tmpdir()
        self.sock = os.path.join(self.dir, "gw.sock")
        self.log = os.path.join(self.dir, "provider.jsonl")
        script = write_script(self.dir, [[{"name": "exec", "arguments": {"command": ["env"]}}]])
        self.proc, _ = start_provider("--unix", self.sock, "--reply", "final:unit", "--log", self.log, "--tool-script", script)

    def tearDown(self):
        self.proc.kill()
        self.proc.wait()

    def log_lines(self):
        with open(self.log, encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    def test_tool_calls_cross_the_wire_both_ways(self):
        tools = agent.door_tools([ECHO])
        messages = [{"role": "system", "content": "use the tools"}, {"role": "user", "content": "go"}]
        first = agent.invoke_model("unix://" + self.sock, TOKEN, "fast", messages, tools)
        self.assertIsInstance(first, agent.ModelReply)
        self.assertEqual(first.text, "")
        self.assertEqual(first.tool_calls, [agent.ToolCall("call_0_0", "exec", {"command": ["env"]})])
        messages.append(agent.assistant_message(first))
        messages.append(agent.tool_message(first.tool_calls[0], "ACCEPTANCE_E2E_MARKER=1"))
        final = agent.invoke_model("unix://" + self.sock, TOKEN, "fast", messages, tools)
        self.assertEqual(final, agent.ModelReply("final:unit", []))
        lines = self.log_lines()
        self.assertEqual(len(lines), 2)
        for r in lines:
            self.assertEqual(r["path"], "/v1/chat/completions")
            self.assertEqual(r["authorization"], "Bearer " + TOKEN)
            self.assertEqual(r["model"], "fast")
            self.assertEqual(r["tools"], ["exec", "spawn", "echo"])
            self.assertFalse([h for h in r["headers"] if h.startswith("x-agenthof")])
        self.assertEqual(lines[1]["tool_rounds"], 1)
        wire = lines[1]["messages"]
        self.assertEqual(wire[-2]["role"], "assistant")
        self.assertEqual(wire[-2]["tool_calls"][0]["id"], "call_0_0")
        self.assertEqual(json.loads(wire[-2]["tool_calls"][0]["function"]["arguments"]), {"command": ["env"]})
        self.assertEqual((wire[-1]["role"], wire[-1]["tool_call_id"], wire[-1]["content"]),
                         ("tool", "call_0_0", "ACCEPTANCE_E2E_MARKER=1"))

    def test_no_tools_means_no_tools_key_on_the_wire(self):
        reply = agent.invoke_model("unix://" + self.sock, TOKEN, "fast", [{"role": "user", "content": "hi"}], [])
        self.assertEqual(reply, agent.ModelReply("final:unit", []))
        self.assertEqual(self.log_lines()[0]["tools"], [])


class _BadArgsHandler(BaseHTTPRequestHandler):
    """Answers every chat completion with one tool call whose arguments
    string is self.server.arguments, which the fake provider cannot produce."""

    def log_message(self, fmt, *args):
        pass

    def address_string(self):
        return "unix"

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        body = json.dumps({
            "id": "chatcmpl-bad", "object": "chat.completion", "created": 0, "model": "fast",
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None,
                "tool_calls": [{"id": "call_bad", "type": "function",
                                "function": {"name": "exec", "arguments": self.server.arguments}}]}}],
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class UnparseableToolCallTest(unittest.TestCase):
    def serve(self, arguments):
        directory = short_tmpdir()
        sock = os.path.join(directory, "bad.sock")
        srv = socketserver.UnixStreamServer(sock, _BadArgsHandler)
        srv.arguments = arguments
        thread = serve(srv)
        self.addCleanup(thread.join)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return "unix://" + sock

    def test_arguments_that_are_not_json_surface_as_a_call_with_no_args(self):
        url = self.serve("not json")
        reply = agent.invoke_model(url, TOKEN, "fast", [{"role": "user", "content": "go"}], agent.door_tools([]))
        self.assertEqual(reply.text, "")
        self.assertEqual(reply.tool_calls, [agent.ToolCall("call_bad", "exec", None)])

    def test_the_conversation_stays_well_formed_after_one(self):
        url = self.serve("not json")
        reply = agent.invoke_model(url, TOKEN, "fast", [{"role": "user", "content": "go"}], agent.door_tools([]))
        msg = agent.assistant_message(reply)
        self.assertEqual(msg["tool_calls"][0]["id"], "call_bad")
        self.assertEqual(json.loads(msg["tool_calls"][0]["function"]["arguments"]), {})


SCRIPTED = agent.Scripted(["env"], "whoami", "echo", "acceptance-worker", "acceptance-sub", 2)
LLM = agent.Llm(SCRIPTED, 8, 240.0)
SPAWN_ARGS = {"role": "acceptance-worker", "workflow": "acceptance-sub", "input": "drive-1"}
ROUNDS = [
    [("exec", {"command": ["env"]})],
    [("whoami", {}), ("echo", {"text": "drive-1"})],
    [("spawn", SPAWN_ARGS), ("spawn", SPAWN_ARGS)],
]


class FakeModel:
    """A tool-calling model with a fixed script: round r is the number of
    assistant tool-call messages already in the conversation. Records every
    call it was asked to make."""

    def __init__(self, rounds, final="final:unit", delay=0.0):
        self.rounds, self.final, self.delay, self.seen = rounds, final, delay, []

    def __call__(self, proxy_url, run_token, model, messages, tools, timeout):
        self.seen.append((proxy_url, run_token, model, [dict(m) for m in messages], [t.name for t in tools], timeout))
        time.sleep(self.delay)
        done = sum(1 for m in messages if m.get("role") == "assistant" and m.get("tool_calls"))
        if done < len(self.rounds):
            return agent.ModelReply("", [agent.ToolCall("call_%d_%d" % (done, i), name, args)
                                         for i, (name, args) in enumerate(self.rounds[done])])
        return agent.ModelReply(self.final, [])


class TimeoutModel(FakeModel):
    """Honours the timeout it is handed, as a real client does: a call that
    would take longer than it is cut off there with a timeout error."""

    def __call__(self, proxy_url, run_token, model, messages, tools, timeout):
        if self.delay > timeout:
            self.seen.append(timeout)
            time.sleep(timeout)
            raise TimeoutError("Request timed out.")
        return super().__call__(proxy_url, run_token, model, messages, tools, timeout)


class EndlessModel(FakeModel):
    """Calls exec every round, forever."""

    def __call__(self, proxy_url, run_token, model, messages, tools, timeout):
        self.seen.append(len(messages))
        return agent.ModelReply("", [agent.ToolCall("call_%d" % len(self.seen), "exec", {"command": ["env"]})])


# Not test_doors.FakeDoorsObject: this one also times exec and can fail or delay it.
class FakeDoors:
    """A Doors stand-in: answers from its settings, records calls with times."""

    def __init__(self, log, exec_out="ACCEPTANCE_E2E_MARKER=1\n", exec_error=None, exec_delay=0.0,
                 spawn_error=None, spawn_delay=0.0, spawn_preview="governed:unit"):
        self.log, self.exec_out, self.exec_error, self.exec_delay = log, exec_out, exec_error, exec_delay
        self.spawn_error, self.spawn_delay, self.spawn_preview = spawn_error, spawn_delay, spawn_preview
        self.closed, self.n, self.lock = False, 0, threading.Lock()

    def exec_run(self, argv):
        start = time.monotonic()
        time.sleep(self.exec_delay)
        self.log.append(("exec", list(argv), start, time.monotonic()))
        if self.exec_error:
            raise self.exec_error
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
        return {"status": "succeeded", "child_run_id": "r-child%d" % n, "output_sha": "ab" * 32,
                "output_preview": self.spawn_preview}

    def close(self):
        self.closed = True


class LlmDriverTest(unittest.TestCase):
    def drive(self, model, doors, tools=(ECHO, WHOAMI), call_tools=None, llm=LLM):
        log = doors.log
        if call_tools is None:
            def call_tools(purl, tok, calls):
                log.append(("tools", purl, tok, calls))
                name, args = calls[0]
                return ["acting as: u-test" if name == "whoami" else args.get("text", "")]
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                return agent.run_llm("unix:///tmp/gw.sock", TOKEN, "fast", "drive-1", llm, invoke_model=model,
                                     list_tools=lambda purl, tok: list(tools), call_tools=call_tools,
                                     doors_factory=lambda purl, tok: doors)
        finally:
            self.stderr = err.getvalue()

    def test_the_model_chooses_every_door_and_the_artifact_reports_each_leg(self):
        log, model = [], FakeModel(ROUNDS)
        doors = FakeDoors(log)
        art = self.drive(model, doors)
        lines = art.splitlines()
        self.assertEqual(lines[:6], [
            "model: called exec",
            "exec: ACCEPTANCE_E2E_MARKER=1",
            "model: called whoami, echo",
            "tool whoami: acting as: u-test",
            "tool echo: drive-1",
            "model: called spawn, spawn",
        ])
        # The two spawn calls run concurrently, so which call gets which child
        # id is not fixed; the lines are in the model's call order either way.
        self.assertEqual(sorted(lines[6:8]), ["spawn: succeeded r-child1 governed:unit", "spawn: succeeded r-child2 governed:unit"])
        self.assertEqual(lines[8:], ["model: final:unit"])
        self.assertEqual(len(model.seen), 4)
        purl, tok, mdl, messages, tools, timeout = model.seen[0]
        self.assertEqual((purl, tok, mdl), ("unix:///tmp/gw.sock", TOKEN, "fast"))
        self.assertEqual(tools, ["exec", "spawn", "echo", "whoami"], "the model is offered the doors plus the real grant")
        self.assertLessEqual(timeout, agent.REQUEST_TIMEOUT)
        self.assertGreater(timeout, agent.REQUEST_TIMEOUT - 5)
        self.assertEqual([m["role"] for m in messages], ["system", "user"])
        self.assertEqual(messages[1]["content"], "drive-1")
        for needle in ('["env"]', "whoami", "echo", "acceptance-worker", "acceptance-sub", "2 sub-agents"):
            self.assertIn(needle, messages[0]["content"])
        last = model.seen[3][3]
        self.assertEqual([m["role"] for m in last], ["system", "user", "assistant", "tool", "assistant", "tool", "tool", "assistant", "tool", "tool"])
        self.assertEqual((last[3]["tool_call_id"], last[3]["content"]), ("call_0_0", "ACCEPTANCE_E2E_MARKER=1\n"))
        self.assertRegex(last[8]["content"], r"^succeeded r-child[12] governed:unit$")
        self.assertEqual(log[0][:2], ("exec", ["env"]))
        self.assertEqual(sorted(e[3][0] for e in log if e[0] == "tools"), [("echo", {"text": "drive-1"}), ("whoami", {})])
        self.assertEqual([e[1:4] for e in log if e[0] == "spawn"], [("acceptance-worker", "acceptance-sub", "drive-1")] * 2)
        self.assertTrue(doors.closed)
        self.assertEqual(self.stderr, "")

    def test_round_calls_run_concurrently(self):
        log = []
        doors = FakeDoors(log, spawn_delay=0.4)
        self.drive(FakeModel(ROUNDS), doors)
        (a0, a1), (b0, b1) = [(e[4], e[5]) for e in log if e[0] == "spawn"]
        self.assertTrue(a0 < b1 and b0 < a1, "the two spawns of one round did not overlap in time")

    def test_refused_door_is_fed_back_as_the_refused_string(self):
        log, model = [], FakeModel(ROUNDS)
        doors = FakeDoors(log, exec_error=agent.DoorError("exec/run answered 403 at unix:///tmp/gw.sock secret-body", 403),
                          spawn_error=agent.DoorError("spawn answered 403", 403))
        art = self.drive(model, doors)
        lines = art.splitlines()
        self.assertEqual(lines[1], "exec: refused by policy")
        self.assertEqual(lines[6:8], ["spawn: refused by policy", "spawn: refused by policy"])
        self.assertEqual(lines[-1], "model: final:unit", "a refusal does not end the step; the model saw it and finished")
        fed = [m["content"] for m in model.seen[3][3] if m["role"] == "tool"]
        self.assertEqual(fed[0], "refused by policy")
        self.assertEqual(fed[3:5], ["refused by policy", "refused by policy"])
        self.assertNotIn("secret-body", art)
        self.assertNotIn("gw.sock", json.dumps(model.seen[3][3]))
        self.assertIn("exec refused by policy: DoorError", self.stderr)
        self.assertNotIn("secret-body", self.stderr)
        self.assertNotIn("gw.sock", self.stderr)

    def test_failed_door_is_fed_back_as_the_failed_string(self):
        for err in (agent.DoorError("exec/run answered 502", 502), agent.DoorError("exec/run answered 503", 503),
                    agent.DoorError("env exited 1", 200), RuntimeError("connection reset at unix:///tmp/gw.sock")):
            with self.subTest(err=err):
                log, model = [], FakeModel(ROUNDS[:1])
                doors = FakeDoors(log, exec_error=err)
                art = self.drive(model, doors)
                self.assertEqual(art.splitlines()[1], "exec: the door call failed")
                self.assertEqual(model.seen[1][3][3]["content"], "the door call failed")
                self.assertNotIn("gw.sock", art)
                self.assertNotIn("gw.sock", self.stderr)
                self.assertIn("exec the door call failed: " + type(err).__name__, self.stderr)

    def test_a_tool_door_error_is_fed_back_as_the_failed_string(self):
        def is_error(purl, tok, calls):
            raise agent.DoorError("tool echo returned an error")
        log, model = [], FakeModel([[("echo", {"text": "drive-1"})]])
        art = self.drive(model, FakeDoors(log), call_tools=is_error)
        self.assertEqual(art.splitlines()[1], "tool echo: the door call failed")
        self.assertEqual(model.seen[1][3][3]["content"], "the door call failed")

    def test_results_are_truncated_before_the_next_round(self):
        log, model = [], FakeModel(ROUNDS[:1])
        doors = FakeDoors(log, exec_out="x" * (3 * agent.TOOL_RESULT_MAX))
        art = self.drive(model, doors)
        fed = model.seen[1][3][3]["content"]
        self.assertTrue(fed.endswith(" [truncated]"))
        self.assertEqual(len(fed), agent.TOOL_RESULT_MAX + len(" [truncated]"))
        self.assertEqual(art.splitlines()[1], "exec: " + fed)

    def test_round_cap_fails_closed(self):
        log, model = [], EndlessModel([])
        doors = FakeDoors(log)
        with self.assertRaises(agent.StepFailed) as cm:
            self.drive(model, doors, llm=agent.Llm(SCRIPTED, 3, 240.0))
        self.assertEqual(cm.exception.reason, "round cap reached")
        self.assertEqual(len(model.seen), 3)
        self.assertEqual(len([e for e in log if e[0] == "exec"]), 3)
        self.assertTrue(doors.closed)

    def test_step_deadline_fails_closed(self):
        log, model = [], EndlessModel([])
        doors = FakeDoors(log, exec_delay=0.2)
        t0 = time.monotonic()
        with self.assertRaises(agent.StepFailed) as cm:
            self.drive(model, doors, llm=agent.Llm(SCRIPTED, 8, 0.3))
        self.assertEqual(cm.exception.reason, "step deadline reached")
        deadline = t0 + 0.3
        execs = [e for e in log if e[0] == "exec"]
        self.assertTrue(execs, "no door call ran at all")
        self.assertTrue(all(e[2] < deadline for e in execs), "a door call was launched after the deadline")
        self.assertGreater(execs[-1][3], deadline, "the call running at the deadline was not let finish")
        self.assertLess(len(execs), 8, "the cap, not the deadline, stopped the loop")
        self.assertTrue(doors.closed)

    def test_deadline_passing_during_the_model_call_starts_no_door_call(self):
        log, model = [], TimeoutModel(ROUNDS, delay=0.3)
        doors = FakeDoors(log)
        with self.assertRaises(agent.StepFailed) as cm:
            self.drive(model, doors, llm=agent.Llm(SCRIPTED, 8, 0.2))
        self.assertEqual(cm.exception.reason, "step deadline reached")
        self.assertEqual(len(model.seen), 1)
        self.assertLessEqual(model.seen[0], 0.2)
        self.assertEqual(log, [], "a door call started after the deadline")
        self.assertTrue(doors.closed)
        self.assertIn("model call cut off by the step deadline: TimeoutError", self.stderr)

    def test_a_model_reply_landing_past_the_deadline_starts_no_door_call(self):
        log, model = [], FakeModel(ROUNDS, delay=0.3)
        doors = FakeDoors(log)
        with self.assertRaises(agent.StepFailed) as cm:
            self.drive(model, doors, llm=agent.Llm(SCRIPTED, 8, 0.2))
        self.assertEqual(cm.exception.reason, "step deadline reached")
        self.assertEqual(log, [], "a door call started after the deadline")

    def test_a_model_failure_before_the_deadline_stays_the_model_reason(self):
        def boom(*a, **k):
            raise TimeoutError("Request timed out.")
        with self.assertRaises(agent.StepFailed) as cm:
            self.drive(boom, FakeDoors([]))
        self.assertEqual((cm.exception.reason, cm.exception.cause), ("model call failed", "TimeoutError"))

    def test_model_chosen_text_is_bounded_in_the_artifact(self):
        long = "n" * (2 * agent.TOOL_RESULT_MAX)
        model = FakeModel([[(long, {})]], final="f" * (2 * agent.TOOL_RESULT_MAX))
        art = self.drive(model, FakeDoors([]))
        lines = art.splitlines()
        self.assertEqual(lines[0], "model: called " + long[:agent.TOOL_RESULT_MAX] + " [truncated]")
        self.assertEqual(lines[1], "tool " + long[:agent.TOOL_RESULT_MAX - 5] + " [truncated]: unknown tool")
        self.assertEqual(lines[2], "model: " + "f" * agent.TOOL_RESULT_MAX + " [truncated]")

    def test_a_round_runs_at_most_max_parallel_calls_at_once(self):
        log, n = [], 3 * agent.MAX_PARALLEL_CALLS
        doors = FakeDoors(log, spawn_delay=0.05)
        in_flight, peak, lock = [0], [0], threading.Lock()
        spawn = doors.spawn

        def counted(*a):
            with lock:
                in_flight[0] += 1
                peak[0] = max(peak[0], in_flight[0])
            try:
                return spawn(*a)
            finally:
                with lock:
                    in_flight[0] -= 1
        doors.spawn = counted
        self.drive(FakeModel([[("spawn", SPAWN_ARGS)] * n]), doors)
        self.assertEqual(len([e for e in log if e[0] == "spawn"]), n, "every call of the round ran")
        self.assertEqual(peak[0], agent.MAX_PARALLEL_CALLS)

    def test_model_timeout_is_bounded_by_the_remaining_budget(self):
        model = FakeModel(ROUNDS[:1], delay=0.1)
        self.drive(model, FakeDoors([]), llm=agent.Llm(SCRIPTED, 8, 5.0))
        first, second = model.seen[0][5], model.seen[1][5]
        self.assertLessEqual(first, 5.0)
        self.assertGreater(first, 4.5)
        self.assertLess(second, first - 0.05, "the second call's timeout is not what is left of the budget")

    def test_unknown_tool_and_invalid_arguments_make_no_door_call(self):
        rounds = [[("nope", {"x": 1}), ("exec", {"command": "env"}), ("exec", {}), ("spawn", {"role": "w"}),
                   ("echo", {"text": "ok"})]]
        log, model = [], FakeModel(rounds)
        art = self.drive(model, FakeDoors(log))
        self.assertEqual(art.splitlines()[1:6], [
            "tool nope: unknown tool",
            "exec: invalid arguments",
            "exec: invalid arguments",
            "spawn: invalid arguments",
            "tool echo: ok",
        ])
        self.assertEqual([e[0] for e in log], ["tools"], "only the well-formed call reached a door")
        fed = [m["content"] for m in model.seen[1][3] if m["role"] == "tool"]
        self.assertEqual(fed[:4], ["unknown tool", "invalid arguments", "invalid arguments", "invalid arguments"])

    def test_unparseable_arguments_make_no_door_call(self):
        rounds = [[("exec", None), ("spawn", None), ("echo", None), ("nope", None)]]
        log, model = [], FakeModel(rounds)
        art = self.drive(model, FakeDoors(log))
        self.assertEqual(art.splitlines()[1:5], [
            "exec: invalid arguments",
            "spawn: invalid arguments",
            "tool echo: invalid arguments",
            "tool nope: invalid arguments",
        ])
        self.assertEqual(log, [], "a call with unparseable arguments reached a door")
        fed = [m["content"] for m in model.seen[1][3] if m["role"] == "tool"]
        self.assertEqual(fed, ["invalid arguments"] * 4)

    def test_tool_name_collision_fails_closed(self):
        model = FakeModel(ROUNDS)
        with self.assertRaises(agent.StepFailed) as cm:
            self.drive(model, FakeDoors([]), tools=(agent.ToolSpec("spawn", "an upstream tool", {"type": "object"}),))
        self.assertEqual(cm.exception.reason, "tool set conflict")
        self.assertEqual(model.seen, [], "no model call is made with an ambiguous tool set")

    def test_discovery_failure_is_the_tool_reason(self):
        def broken(purl, tok):
            raise agent.DoorError("tool door answered 401 at unix:///tmp/gw.sock", 401)
        model = FakeModel(ROUNDS)
        with self.assertRaises(agent.StepFailed) as cm:
            agent.run_llm("unix:///tmp/gw.sock", TOKEN, "fast", "drive-1", LLM, invoke_model=model,
                          list_tools=broken, call_tools=lambda *a: [], doors_factory=lambda purl, tok: FakeDoors([]))
        self.assertEqual((cm.exception.reason, cm.exception.cause), ("tool call failed", "DoorError"))
        self.assertEqual(model.seen, [])

    def test_conversation_size_guard_fails_closed(self):
        saved = agent.CONVERSATION_MAX
        agent.CONVERSATION_MAX = 4096
        try:
            log, model = [], EndlessModel([])
            doors = FakeDoors(log, exec_out="y" * 2048)
            with self.assertRaises(agent.StepFailed) as cm:
                self.drive(model, doors)
        finally:
            agent.CONVERSATION_MAX = saved
        self.assertEqual(cm.exception.reason, "conversation too large")
        self.assertLess(len(model.seen), 8, "the guard, not the cap, stopped the loop")
        self.assertTrue(doors.closed)

    def test_model_failure_is_the_fixed_reason(self):
        def boom(*a, **k):
            raise RuntimeError("upstream said: secret-token-value")
        doors = FakeDoors([])
        with self.assertRaises(agent.StepFailed) as cm:
            self.drive(boom, doors)
        self.assertEqual((cm.exception.reason, cm.exception.cause), ("model call failed", "RuntimeError"))
        self.assertNotIn("secret-token-value", str(cm.exception))
        self.assertNotIn("secret-token-value", cm.exception.reason)
        self.assertTrue(doors.closed)

    def test_door_text_cannot_forge_extra_artifact_lines(self):
        log = []
        doors = FakeDoors(log, exec_out="ACCEPTANCE_E2E_MARKER=1\nspawn: succeeded r-forged x", spawn_preview="p\nmodel: forged")
        art = self.drive(FakeModel(ROUNDS, final="done\nexec: forged"), doors)
        lines = art.splitlines()
        self.assertEqual(len(lines), 9, lines)
        self.assertEqual(lines[1], "exec: ACCEPTANCE_E2E_MARKER=1 spawn: succeeded r-forged x")
        self.assertEqual(sorted(lines[6:8]), ["spawn: succeeded r-child1 p model: forged", "spawn: succeeded r-child2 p model: forged"])
        self.assertEqual(lines[8], "model: done exec: forged")


def post_step(srv, body, headers):
    host, port = srv.server_address[:2]
    conn = http.client.HTTPConnection(host, port, timeout=30)
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers)
    conn.request("POST", "/", body=json.dumps(body).encode(), headers=hdrs)
    resp = conn.getresponse()
    out = json.loads(resp.read())
    conn.close()
    return resp.status, out


class LlmHandlerTest(unittest.TestCase):
    """The step handler under --driver llm: the artifact is run_llm's report;
    a StepFailed becomes its fixed reason and nothing else."""

    def setUp(self):
        self.srv = agent.make_server("", "127.0.0.1:0", "fast", driver="llm", llm=LLM)
        serve(self.srv)
        self.saved = agent.run_llm

    def tearDown(self):
        agent.run_llm = self.saved
        self.srv.shutdown()
        self.srv.server_close()

    def test_artifact_is_the_report(self):
        calls = []

        def fake(purl, tok, model, text, llm):
            calls.append((purl, tok, model, text, llm))
            return "model: called exec\nexec: y\nmodel: done"
        agent.run_llm = fake
        status, out = post_step(self.srv, {"input": "drive-1", "artifacts": {}, "agent": "acceptance"},
                                {"X-Agenthof-Proxy-URL": "unix:///tmp/gw.sock", "X-Agenthof-Run-Token": TOKEN})
        self.assertEqual((status, out), (200, {"artifact": "model: called exec\nexec: y\nmodel: done", "success": True}))
        self.assertEqual(calls, [("unix:///tmp/gw.sock", TOKEN, "fast", "drive-1", LLM)])

    def test_step_failed_carries_only_the_fixed_reason(self):
        def fake(*a, **k):
            raise agent.StepFailed("round cap reached", "StepFailed")
        agent.run_llm = fake
        status, out = post_step(self.srv, {"input": "drive-1"},
                                {"X-Agenthof-Proxy-URL": "unix:///tmp/gw.sock", "X-Agenthof-Run-Token": TOKEN})
        self.assertEqual((status, out), (200, {"artifact": "", "success": False, "reason": "round cap reached"}))


class LlmDriverOverUnixSocketTest(unittest.TestCase):
    """The real driver end to end: the real invoke_model (ChatOpenAI.bind_tools)
    over a Unix socket against the fake tool-calling provider, with the door
    clients faked. Proves the loop and the transport agree on the wire."""

    def setUp(self):
        self.dir = short_tmpdir()
        self.sock = os.path.join(self.dir, "gw.sock")
        self.log = os.path.join(self.dir, "provider.jsonl")
        rounds = [[{"name": n, "arguments": a} for n, a in r] for r in ROUNDS]
        script = write_script(self.dir, rounds)
        self.proc, _ = start_provider("--unix", self.sock, "--reply", "final:uds", "--log", self.log, "--tool-script", script)

    def tearDown(self):
        self.proc.kill()
        self.proc.wait()

    def test_every_door_through_the_real_model_shell(self):
        log = []
        doors = FakeDoors(log)

        def call_tools(purl, tok, calls):
            name, args = calls[0]
            return ["acting as: u-test" if name == "whoami" else args["text"]]
        # The tool door lists its tools sorted by name.
        art = agent.run_llm("unix://" + self.sock, TOKEN, "fast", "drive-1", LLM,
                            list_tools=lambda purl, tok: [ECHO, WHOAMI], call_tools=call_tools,
                            doors_factory=lambda purl, tok: doors)
        self.assertEqual(art.splitlines()[-1], "model: final:uds")
        self.assertEqual(len(art.splitlines()), 9)
        with open(self.log, encoding="utf-8") as f:
            lines = [json.loads(l) for l in f]
        self.assertEqual([r["tool_rounds"] for r in lines], [0, 1, 2, 3])
        self.assertTrue(all(r["tools"] == ["exec", "spawn", "echo", "whoami"] for r in lines))
        self.assertEqual([e[0] for e in log if e[0] != "tools"], ["exec", "spawn", "spawn"])

    def test_the_step_server_serves_driver_llm_over_the_socket(self):
        """The same, through the step server main() builds: POST a step to the
        handler and read the artifact from its reply."""
        log = []
        doors = FakeDoors(log)
        srv = agent.make_server("", "127.0.0.1:0", "fast", driver="llm", llm=LLM)
        serve(srv)
        saved = agent.run_llm

        def run(purl, tok, model, text, llm):
            return saved(purl, tok, model, text, llm,
                         list_tools=lambda p, t: [ECHO, WHOAMI],
                         call_tools=lambda p, t, calls: ["acting as: u-test" if calls[0][0] == "whoami" else calls[0][1]["text"]],
                         doors_factory=lambda p, t: doors)
        agent.run_llm = run
        try:
            status, out = post_step(srv, {"input": "drive-1"},
                                    {"X-Agenthof-Proxy-URL": "unix://" + self.sock, "X-Agenthof-Run-Token": TOKEN})
        finally:
            agent.run_llm = saved
            srv.shutdown()
            srv.server_close()
        self.assertEqual((status, out["success"]), (200, True))
        self.assertEqual(out["artifact"].splitlines()[-1], "model: final:uds")
        self.assertEqual(len(out["artifact"].splitlines()), 9)


if __name__ == "__main__":
    unittest.main()
