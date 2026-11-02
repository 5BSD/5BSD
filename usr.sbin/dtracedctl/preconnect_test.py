# SPDX-License-Identifier: BSD-2-Clause
"""Only source-verified parser paths which return before open_dtraced()."""
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"]
PROGRAM = ROOT / "usr.sbin/dtracedctl/dtracedctl"
ENV = {"PATH": "", "LC_ALL": "C", "LD_LIBRARY_PATH":
       ":".join(str(ROOT / name) for name in ("lib/libc", "lib/libsys"))}


class PreconnectArguments(unittest.TestCase):
    def invoke(self, arguments, expected):
        self.assertNotEqual(os.geteuid(), 0, "run pre-connect cases as an ordinary user")
        result = subprocess.run([str(PROGRAM), *arguments], env=ENV,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, expected, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("connection failed", result.stderr)
        return result.stderr

    def test_help(self):
        text = self.invoke(["--help"], 0)
        for name in ["Usage:", "--cleanup-state", "--show-stats"]:
            self.assertIn(name, text)

    def test_missing_action(self):
        self.assertIn("Usage:", self.invoke([], 64))

    def test_unknown_option(self):
        self.assertIn("Usage:", self.invoke(["--not-an-option"], 1))

    def test_conflicting_actions(self):
        self.assertIn("Usage:", self.invoke(["--cleanup-state", "--show-stats"], 64))

    def test_invalid_name_lists(self):
        for name in ["", ",vm", "vm,", "vm,,other", "x" * 4096]:
            for option in ["--cleanup-state=", "--show-stats="]:
                with self.subTest(option=option, length=len(name)):
                    self.assertIn("invalid VM names", self.invoke([option + name], 64))

    def test_unexpected_positional_names(self):
        for arguments in [["vm"], ["--show-stats=vm", "other"], ["--show-stats", "one", "two"]]:
            with self.subTest(arguments=arguments):
                self.assertIn("invalid VM names", self.invoke(arguments, 64))


if __name__ == "__main__":
    unittest.main()
