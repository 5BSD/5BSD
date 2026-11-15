# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Check real retained-symbol artifacts and reject damaged split-debug pairs."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

parser = argparse.ArgumentParser()
for name in ('binary', 'debug', 'strip'):
    parser.add_argument('--' + name, type=Path, required=True)
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining
root = Path(os.environ.get('TEST_SRCDIR', '/'))
for name, value in vars(args).items():
    setattr(args, name, (root / value).resolve(strict=True))
spec = importlib.util.spec_from_file_location('debug_check', Path(__file__).with_name('elf-debug-check.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class RetainedSymbolsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_actual_retained_symbol_pair(self):
        self.assertEqual(checker.verify(args.binary, args.debug, retain_symbols=True)['status'], 'passed')

    def test_default_requires_stripped_symbols(self):
        with self.assertRaisesRegex(ValueError, 'retains static symbol sections'):
            checker.verify(args.binary, args.debug)

    def test_removed_required_symbols_rejected(self):
        binary = self.root / args.binary.name
        subprocess.run([str(args.strip), '--strip-all', '-o', str(binary), str(args.binary)],
                       check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, 'lacks its required static symbol table'):
            checker.verify(binary, args.debug, retain_symbols=True)

    def test_damaged_debug_payload_rejected(self):
        data = bytearray(args.debug.read_bytes())
        data[-1] ^= 1
        debug = self.root / args.debug.name
        debug.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'debug link CRC differs'):
            checker.verify(args.binary, debug, retain_symbols=True)

    def test_wrong_debug_filename_rejected(self):
        debug = self.root / 'wrong-name.debug'
        debug.write_bytes(args.debug.read_bytes())
        with self.assertRaisesRegex(ValueError, 'debug link name differs'):
            checker.verify(args.binary, debug, retain_symbols=True)

    def test_conflicting_policy_rejected(self):
        for policy in ('module', 'kernel'):
            with self.subTest(policy=policy), self.assertRaisesRegex(ValueError, 'choose ordinary retained-symbol'):
                checker.verify(args.binary, args.debug, retain_symbols=True, **{policy: True})


if __name__ == '__main__':
    unittest.main()
