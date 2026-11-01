# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the source-verified help path before any device/service operation."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class HelpTest(unittest.TestCase):
    def test_help_has_no_filesystem_side_effects(self):
        root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([str(root / 'usr.sbin/ctladm/ctladm'), *['help']],
                cwd=temporary, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertIn('Usage:', result.stdout)
            self.assertEqual(result.stderr, '')
            self.assertEqual(list(Path(temporary).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
