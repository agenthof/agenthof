"""Tests for deploy/refexec/refexec-run-seatbelt.sh (run: python -m unittest discover -s scripts -p 'test_*.py').
A fake refexec reports the -check lines and records that it was started; no sandbox is needed."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LAUNCHER = REPO / "deploy" / "refexec" / "refexec-run-seatbelt.sh"

# `refexec -config C -check` prints $CHECK_OUTPUT; a plain start records itself.
FAKE_REFEXEC = """#!/bin/sh
case "$*" in
	*-check*) printf '%s' "$CHECK_OUTPUT" ;;
	*) echo started >"$STARTED_MARK" ;;
esac
"""


class RefexecRunSeatbeltTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.bin = root / "refexec"
        self.bin.write_text(FAKE_REFEXEC)
        self.bin.chmod(0o755)
        self.sock_dir = root / "sock"
        self.store = root / "stores" / "work"
        self.started = root / "started"

    def tearDown(self):
        self.tmp.cleanup()

    def launch(self, check_output):
        env = dict(os.environ, REFEXEC_BIN=str(self.bin), REFEXEC_CONFIG="unused.yaml",
                   CHECK_OUTPUT=check_output, STARTED_MARK=str(self.started))
        return subprocess.run(["bash", str(LAUNCHER)], env=env, capture_output=True, text=True)

    def test_the_three_lines_create_the_private_dirs_and_start_refexec(self):
        out = f"socket={self.sock_dir}/r.sock\nworkspace=work\nstore_path={self.store}\n"
        res = self.launch(out)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.store.stat().st_mode & 0o777, 0o700)
        # The store root did not exist either: created along the way, it is
        # 0700 too, not the umask default a bare `mkdir -p -m` would leave.
        self.assertEqual(self.store.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.sock_dir.stat().st_mode & 0o777, 0o700)
        self.assertTrue(self.started.exists(), "the launcher must hand over to refexec")

    def test_an_extra_line_is_refused_before_anything_is_created(self):
        out = f"socket={self.sock_dir}/r.sock\nworkspace=work\nstore_path={self.store}\nsurprise=1\n"
        res = self.launch(out)
        self.assertEqual(res.returncode, 1)
        self.assertIn("unexpected -check output", res.stderr)
        self.assertFalse(self.store.exists())
        self.assertFalse(self.started.exists())

    def test_the_podman_shaped_output_is_refused(self):
        # A podman config run through this launcher reports no store_path.
        res = self.launch(f"socket={self.sock_dir}/r.sock\nworkspace=work:/work\n")
        self.assertEqual(res.returncode, 1)
        self.assertFalse(self.started.exists())


if __name__ == "__main__":
    unittest.main()
