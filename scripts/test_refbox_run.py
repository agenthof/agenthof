"""Tests for deploy/refbox/refbox-run.sh (run: python -m unittest discover -s scripts -p 'test_*.py').
A fake podman on PATH records the argv the recipe builds; no container runtime is needed."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RECIPE = REPO / "deploy" / "refbox" / "refbox-run.sh"

FAKE_PODMAN = """#!/bin/sh
# one argument per line, so a test can assert on exact argv slots
for a in "$@"; do printf '%s\\n' "$a"; done >"$PODMAN_ARGV"
"""


class RefboxRunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        bin_dir = Path(self.tmp.name) / "bin"
        bin_dir.mkdir()
        (bin_dir / "podman").write_text(FAKE_PODMAN)
        (bin_dir / "podman").chmod(0o755)
        self.sock_dir = Path(self.tmp.name) / "sock"
        self.sock_dir.mkdir()
        self.argv_file = Path(self.tmp.name) / "argv"
        self.env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}",
                        PODMAN_ARGV=str(self.argv_file), AGENTHOF_REFBOX_SOCKET_DIR=str(self.sock_dir),
                        REFBOX_DETACH="1", REFBOX_IMAGE="img:test", REFBOX_NAME="box", REFBOX_SOCKET="a.sock")
        self.env.pop("REFBOX_ARGS", None)

    def tearDown(self):
        self.tmp.cleanup()

    def run_recipe(self, **extra):
        env = dict(self.env, **extra)
        subprocess.run(["bash", str(RECIPE)], env=env, check=True, capture_output=True)
        return self.argv_file.read_text().splitlines()

    def test_without_the_knob_argv_ends_at_the_socket(self):
        argv = self.run_recipe()
        self.assertEqual(argv[-3:], ["img:test", "-socket", f"{self.sock_dir}/a.sock"])
        self.assertEqual(argv[:2], ["run", "-d"])
        self.assertIn("--network", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "none")

    def test_the_knob_appends_after_the_socket_word_split(self):
        argv = self.run_recipe(REFBOX_ARGS="--driver scripted --spawns 2")
        self.assertEqual(argv[-7:], ["img:test", "-socket", f"{self.sock_dir}/a.sock", "--driver", "scripted", "--spawns", "2"])

    def test_an_empty_knob_is_the_default(self):
        self.assertEqual(self.run_recipe(REFBOX_ARGS=""), self.run_recipe())


if __name__ == "__main__":
    unittest.main()
