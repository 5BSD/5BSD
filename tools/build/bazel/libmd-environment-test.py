#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Validate selected compiler identity through the aliases used by Make."""
from pathlib import Path
import tempfile
import unittest

from libmd_environment import same_executable


class CompilerIdentityTests(unittest.TestCase):
    def test_symlink_and_hardlink_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compiler = root / 'clang'
            compiler.write_bytes(b'compiler')
            symlink = root / 'clang-symlink'
            symlink.symlink_to(compiler.name)
            hardlink = root / 'cc'
            hardlink.hardlink_to(compiler)
            other = root / 'other'
            other.write_bytes(b'other executable')

            self.assertTrue(same_executable(symlink, compiler))
            self.assertTrue(same_executable(hardlink, compiler))
            self.assertFalse(same_executable(other, compiler))
            self.assertFalse(same_executable(root / 'missing', compiler))


if __name__ == '__main__':
    unittest.main()
