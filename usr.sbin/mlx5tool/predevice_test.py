# SPDX-License-Identifier: BSD-2-Clause
"""Source-reviewed argument paths that return before opening a device."""
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"]
PROGRAM = ROOT / "usr.sbin/mlx5tool/mlx5tool"
ENV = {"PATH": "", "LC_ALL": "C", "LD_LIBRARY_PATH": ":".join(str(ROOT / name) for name in
       ["lib/libc", "lib/libsys", "lib/libpcap", "lib/ofed/libibverbs", "lib/ofed/libbnxtre", "lib/ofed/libmlx5", "lib/libthr"])}


class PredeviceArguments(unittest.TestCase):
    def invoke(self, arguments, expected, stdout=False):
        self.assertNotEqual(os.geteuid(), 0, "run parser cases as an ordinary user")
        result = subprocess.run([str(PROGRAM), *arguments], env=ENV,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, expected, result.stderr)
        text = result.stdout if stdout else result.stderr
        self.assertEqual(result.stderr if stdout else result.stdout, "")
        return text

    def test_help(self):
        self.assertIn("Usage: mlx5tool", self.invoke(["-h"], 1))

    def test_missing_action(self):
        self.assertIn("Usage: mlx5tool", self.invoke([], 1))

    def test_unknown_option(self):
        self.assertIn("Usage: mlx5tool", self.invoke(["-X"], 1))

    def test_invalid_selector(self):
        self.assertIn("invalid pci address", self.invoke(["-d", "invalid", "-r"], 1))


if __name__ == "__main__":
    unittest.main()
