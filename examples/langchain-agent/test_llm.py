"""Tests for the llm driver in examples/langchain-agent/agent.py: the neutral
door-tool specs, the LangChain model shell over a Unix socket, and run_llm
driven by a fake tool-calling model with the door clients injected.
Run from the repo root: python -m unittest discover -s examples/langchain-agent -p 'test_*.py' -v
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent  # noqa: E402

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
