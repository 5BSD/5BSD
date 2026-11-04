# SPDX-License-Identifier: BSD-2-Clause
"""Execute real userboot harness error paths; shared-loader callback execution is separate."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

parser = argparse.ArgumentParser()
for key in ['program', 'loader']:
    parser.add_argument('--' + key, type=Path, required=True)
parser.add_argument('--libraries', type=Path, nargs='+', required=True)
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining


class UserbootHarness(unittest.TestCase):
    def invoke(self, *options):
        libraries = ':'.join(sorted({str(p.resolve(strict=True).parent) for p in args.libraries}))
        return subprocess.run([str(args.loader), '-o', 'LIBRARY_PATH=' + libraries, '--',
                               str(args.program), *options],
                              env={'LC_ALL': 'C'}, capture_output=True, text=True, timeout=15)

    def test_original_usage_path(self):
        result = self.invoke('-?')
        self.assertEqual(result.returncode, 1)
        self.assertIn('usage: [-b <userboot shared object>]', result.stdout)

    def test_missing_shared_object(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / 'missing-userboot.so'
            result = self.invoke('-b', str(missing))
            self.assertEqual(result.returncode, 1)
            self.assertIn(missing.name, result.stdout)
            self.assertFalse(missing.exists())

    def test_original_disk_open_error(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / 'missing-disk.img'
            result = self.invoke('-d', str(missing))
            self.assertEqual(result.returncode, 1)
            self.assertIn("Can't open disk image", result.stderr)
            self.assertIn(str(missing), result.stderr)
            self.assertFalse(missing.exists())


if __name__ == '__main__':
    unittest.main()
