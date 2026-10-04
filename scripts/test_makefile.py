"""Tests for the repository Makefile (run: python -m unittest discover -s scripts -p 'test_*.py').
`make -n` prints what a target would run without running it, so no podman or VM is needed."""
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def make_n(*args):
    return subprocess.run(["make", "-n", "-C", str(REPO), *args], capture_output=True, text=True)


class MakefileTest(unittest.TestCase):
    def test_darwin_goes_through_lima(self):
        res = make_n("acceptance-podman", "UNAME_S=Darwin")
        self.assertEqual(res.returncode, 0, res.stderr)
        # drop make's own "Entering/Leaving directory" lines and strip the trailing
        # space GNU make 3.81 leaves when $(KEEP_FLAG) is empty
        lines = [l.strip() for l in res.stdout.splitlines() if l.strip() and not l.startswith("make:")]
        self.assertEqual(lines, ["deploy/lima/lima.sh up", "deploy/lima/lima.sh e2e acceptance"])

    def test_darwin_keep_is_forwarded(self):
        res = make_n("acceptance-podman", "UNAME_S=Darwin", "KEEP=1")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("deploy/lima/lima.sh e2e acceptance --keep", res.stdout)

    def test_linux_runs_the_script_natively_behind_a_podman_guard(self):
        res = make_n("acceptance-podman", "UNAME_S=Linux", "KEEP=1")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("command -v podman", res.stdout)
        self.assertIn("scripts/e2e-acceptance.sh --keep", res.stdout)
        self.assertNotIn("lima.sh", res.stdout)

    def test_unsupported_host_message(self):
        res = make_n("acceptance-podman", "UNAME_S=FreeBSD")
        self.assertEqual(res.returncode, 0, res.stderr)  # -n prints the recipe; the recipe itself exits 1
        self.assertIn("unsupported host FreeBSD", res.stdout)
        self.assertIn("exit 1", res.stdout)
        self.assertNotIn("deploy/lima", res.stdout)
        # the message names the script; the recipe must not RUN it
        self.assertFalse(any(l.strip().startswith("scripts/e2e-acceptance.sh") for l in res.stdout.splitlines()), res.stdout)

    def test_help_is_the_default_goal(self):
        res = make_n()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("acceptance-podman", res.stdout)
        self.assertIn("KEEP=1", res.stdout)


if __name__ == "__main__":
    unittest.main()
