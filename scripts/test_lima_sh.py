"""Tests for deploy/lima/lima.sh's argument handling (run: python -m unittest discover -s scripts -p 'test_*.py').
A fake limactl on PATH answers `list` and records every `shell` command; no VM is touched."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LIMA = REPO / "deploy" / "lima" / "lima.sh"

FAKE_LIMACTL = """#!/bin/sh
# records each invocation on one line; answers `list` as if the VM exists and runs
printf '%s\\n' "$*" >>"$LIMACTL_LOG"
case "$1" in
  list) case "$*" in *--format*) echo Running ;; *) echo agenthof ;; esac ;;
esac
exit 0
"""


class LimaShTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        bin_dir = Path(self.tmp.name) / "bin"
        bin_dir.mkdir()
        (bin_dir / "limactl").write_text(FAKE_LIMACTL)
        (bin_dir / "limactl").chmod(0o755)
        self.log = Path(self.tmp.name) / "limactl.log"
        self.env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", LIMACTL_LOG=str(self.log))

    def tearDown(self):
        self.tmp.cleanup()

    def lima(self, *args):
        res = subprocess.run(["bash", str(LIMA), *args], env=self.env, capture_output=True, text=True)
        calls = self.log.read_text().splitlines() if self.log.exists() else []
        return res, calls

    def shell_cmds(self, calls):
        return [c for c in calls if c.startswith("shell ")]

    def test_e2e_acceptance_runs_the_script_and_cleans(self):
        res, calls = self.lima("e2e", "acceptance")
        self.assertEqual(res.returncode, 0, res.stderr)
        cmds = self.shell_cmds(calls)
        self.assertTrue(any(c.endswith("bash scripts/e2e-acceptance.sh") for c in cmds), cmds)
        # cmd_clean's command is multi-line, so its prune line is not a "shell " line: search the whole log
        self.assertIn("podman container prune", "\n".join(calls))

    def test_keep_is_forwarded_and_skips_the_prune(self):
        res, calls = self.lima("e2e", "acceptance", "--keep")
        self.assertEqual(res.returncode, 0, res.stderr)
        cmds = self.shell_cmds(calls)
        self.assertTrue(any(c.endswith("bash scripts/e2e-acceptance.sh --keep") for c in cmds), cmds)
        self.assertNotIn("podman container prune", "\n".join(calls))

    def test_all_ends_with_acceptance(self):
        res, calls = self.lima("e2e", "all")
        self.assertEqual(res.returncode, 0, res.stderr)
        scripts = [c.split("bash -lc ", 1)[1] for c in self.shell_cmds(calls) if "scripts/e2e-" in c]
        self.assertEqual(scripts, ["bash scripts/e2e-refbox.sh", "bash scripts/e2e-refbridge.sh",
                                   "bash scripts/e2e-refexec.sh", "bash scripts/e2e-refspawn.sh",
                                   "bash scripts/e2e-acceptance.sh"])

    def test_unknown_word_dies_and_names_acceptance(self):
        res, _ = self.lima("e2e", "spawn")
        self.assertEqual(res.returncode, 1)
        self.assertIn("acceptance", res.stderr)

    def test_build_includes_the_langchain_image(self):
        res, calls = self.lima("build")
        self.assertEqual(res.returncode, 0, res.stderr)
        joined = "\n".join(self.shell_cmds(calls))
        self.assertIn("deploy/refbox/Containerfile.python -t refbox-langchain:test", joined)
        self.assertIn("deploy/refbox/Containerfile -t refbox-echo:test", joined)
        self.assertIn("deploy/refbridge/Containerfile -t refbridge:test", joined)

    def test_up_on_a_running_vm_does_not_start_it(self):
        res, calls = self.lima("up")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(any(c.startswith("start ") for c in calls), calls)
        self.assertTrue(self.shell_cmds(calls), calls)  # the readiness probe still runs


if __name__ == "__main__":
    unittest.main()
