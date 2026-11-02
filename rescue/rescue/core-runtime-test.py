# SPDX-License-Identifier: BSD-2-Clause
"""Safe real rescue application dispatch with private files and stdin only."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

PROGRAM = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"] / "rescue/rescue/rescue_core"

class RescueCore(unittest.TestCase):
    def run_app(self, *args, data=b"", name=None):
        env = dict(os.environ, DTRACE_DOF_INIT_DISABLE="1", LC_ALL="C")
        # This binary is statically linked. No host library/path fallback is used.
        return subprocess.run([name or str(PROGRAM), *args], executable=str(PROGRAM),
            input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, timeout=10, check=False)

    def test_catalog(self):
        p = self.run_app("--list")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(set(p.stdout.split()), {b"cat", b"echo", b"head"})

    def test_echo(self):
        p = self.run_app("echo", "alpha", "beta")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"alpha beta\n", b""))

    def test_echo_without_newline(self):
        p = self.run_app("echo", "-n", "alpha")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"alpha", b""))

    def test_cat_binary_stdin(self):
        data = b"a\x00b\n" * 1000
        p = self.run_app("cat", data=data)
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, data, b""))

    def test_cat_private_file(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"one\ntwo\n")
            p = self.run_app("cat", str(path))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"one\ntwo\n", b""))

    def test_head_stdin(self):
        p = self.run_app("head", "-n", "2", data=b"one\ntwo\nthree\n")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"one\ntwo\n", b""))

    def test_head_private_file(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"one\ntwo\nthree\n")
            p = self.run_app("head", "-n", "1", str(path))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"one\n", b""))

    def test_missing_file(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "absent"
            p = self.run_app("cat", str(path))
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(p.stdout, b"")
            self.assertIn(str(path).encode(), p.stderr)

    def test_unknown_program(self):
        p = self.run_app("missing-program")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b"usage:", p.stderr)

    def test_argv0_dispatch(self):
        p = self.run_app("alpha", "beta", name="echo")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"alpha beta\n", b""))

if __name__ == "__main__":
    unittest.main()
