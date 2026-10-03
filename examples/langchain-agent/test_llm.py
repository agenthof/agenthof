"""Tests for the llm driver in examples/langchain-agent/agent.py: the neutral
door-tool specs, the LangChain model shell over a Unix socket, and run_llm
driven by a fake tool-calling model with the door clients injected.
Run from the repo root: python -m unittest discover -s examples/langchain-agent -p 'test_*.py' -v
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()


def short_tmpdir():
    return tempfile.mkdtemp(dir="/tmp")  # Unix socket paths have a small length limit


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
