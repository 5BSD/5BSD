# SPDX-License-Identifier: BSD-2-Clause
"""Execute the original generated dispatcher with side-effect-free entries."""
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

MINI = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"] / "tools/build/bazel/tests/crunchgen/mini"

class DispatcherTests(unittest.TestCase):
    def run_mini(self, args, executable=MINI):
        return subprocess.run([str(executable), *args], capture_output=True, text=True,
                              env=dict(os.environ, DTRACE_DOF_INIT_DISABLE="1"), timeout=15)

    def test_program(self):
        p = self.run_mini(["alpha", "payload"])
        self.assertEqual((p.returncode, p.stdout, p.stderr), (17, "alpha:2:alpha:payload\n", ""))

    def test_alias_and_identifier(self):
        p = self.run_mini(["[", "arg"])
        self.assertEqual((p.returncode, p.stdout, p.stderr), (23, "two:2:[:arg\n", ""))

    def test_ordered_list(self):
        p = self.run_mini(["--list"])
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, "alpha\na\ntwo-name\n[\n", ""))

    def test_unknown(self):
        p = self.run_mini(["not-an-entry"])
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stdout, "")
        self.assertIn("not-an-entry not compiled in", p.stderr)

    def test_usage(self):
        p = self.run_mini([])
        self.assertEqual(p.returncode, 0)
        self.assertIn("usage: mini", p.stdout)

    def test_private_hardlink_dispatch(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as directory:
            copy = Path(directory) / "mini"
            shutil.copyfile(MINI, copy)
            copy.chmod(0o555)
            link = Path(directory) / "a"
            os.link(copy, link)
            p = self.run_mini(["arg"], link)
            self.assertEqual((p.returncode, p.stdout, p.stderr), (17, "alpha:2:" + str(link) + ":arg\n", ""))

if __name__ == "__main__":
    unittest.main()
