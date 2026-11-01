# SPDX-License-Identifier: BSD-2-Clause
"""Source-reviewed argument paths that return before opening a device."""
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"]
PROGRAM = ROOT / "usr.sbin/cxgbetool/cxgbetool"
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

    def test_short_help(self):
        self.assertIn("Usage:", self.invoke(["-h"], 0, stdout=True))

    def test_long_help(self):
        self.assertIn("Usage:", self.invoke(["--help"], 0, stdout=True))

    def test_missing_device_and_command(self):
        self.assertIn("Usage:", self.invoke([], 22))

    def test_missing_command(self):
        self.assertIn("Usage:", self.invoke(["not-a-device"], 22))


if __name__ == "__main__":
    unittest.main()
