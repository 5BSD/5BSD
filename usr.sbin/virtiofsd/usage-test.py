# SPDX-License-Identifier: BSD-2-Clause
"""Reject incomplete command lines before opening an export or socket."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class UsageTest(unittest.TestCase):
    def test_usage_exits_before_opening_export(self):
        root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([str(root / 'usr.sbin/virtiofsd/virtiofsd')],
                cwd=temporary, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 64)
            self.assertIn('usage: virtiofsd', result.stderr)
            self.assertEqual(result.stdout, '')
            self.assertEqual(list(Path(temporary).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
