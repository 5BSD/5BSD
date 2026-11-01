# SPDX-License-Identifier: BSD-2-Clause
"""Only argument errors which return before socket/address/PAM operations."""
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"]
ENV = {"PATH": "", "LC_ALL": "C", "LD_LIBRARY_PATH": ":".join(str(ROOT / name) for name in
       ["lib/libedit", "lib/ncurses/tinfo", "lib/libthr", "lib/libc", "lib/libsys"])}


class Usage(unittest.TestCase):
    def check(self, arguments):
        self.assertNotEqual(os.geteuid(), 0)
        result = subprocess.run([str(ROOT / "usr.sbin/pppctl/pppctl"), *arguments], env=ENV,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("usage: pppctl", result.stderr)
        self.assertIn("Port|LocalSock", result.stderr)

    def test_missing_endpoint(self):
        self.check([])

    def test_unknown_option(self):
        self.check(["-X"])

    def test_verbose_requires_endpoint(self):
        self.check(["-v"])


if __name__ == "__main__":
    unittest.main()
