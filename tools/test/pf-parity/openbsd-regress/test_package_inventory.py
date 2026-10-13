#!/usr/bin/env python3
"""Check PF archive variants after retirement of the native libpfctl."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]

class PackageInventory(unittest.TestCase):
    def test_supported_archive_variants(self):
        with tempfile.TemporaryDirectory() as temp:
            for debug in (False, True):
                for man in (False, True):
                    options = [('WITH_' if debug else 'WITHOUT_') + 'DEBUG_FILES=yes',
                               ('WITH_' if man else 'WITHOUT_') + 'MANSPLITPKG=yes']
                    actual = subprocess.check_output(
                        ['make', '-C', str(ROOT / 'packages/pf'), '-V', '_ALLPACKAGES',
                         'REPODIR=' + temp, 'PKG_VERSION=1', 'PKG_ABI=FreeBSD:16:amd64',
                         *options], text=True).split()
                    expected = ['pf'] + (['pf-dbg'] if debug else []) + (['pf-man'] if man else [])
                    self.assertEqual(sorted(actual), sorted(expected))

if __name__ == '__main__':
    unittest.main()
