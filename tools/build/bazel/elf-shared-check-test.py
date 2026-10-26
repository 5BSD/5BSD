#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Negative metadata tests based on an explicit real Make-built shared object."""
import argparse
import importlib.util
from pathlib import Path
import re
import sys
import unittest

spec = importlib.util.spec_from_file_location('elf_shared_check', Path(__file__).with_name('elf-shared-check.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SharedTest(unittest.TestCase):
    def test_reference_is_accepted(self):
        module.validate(self.reference, self.reference, self.soname)

    def test_missing_identity_rejected(self):
        text = re.sub(r'^.*\(SONAME\).*$\n?', '', self.text, flags=re.M)
        with self.assertRaisesRegex(ValueError, 'identity'):
            module.parse(text)

    def test_ambiguous_identity_rejected(self):
        line = next(line for line in self.text.splitlines() if '(SONAME)' in line)
        with self.assertRaisesRegex(ValueError, 'identity'):
            module.parse(self.text + '\n' + line)

    def test_dependency_drift_rejected(self):
        record = dict(self.reference, needed=self.reference['needed'] + ['libunexpected.so.1'])
        with self.assertRaisesRegex(ValueError, 'needed'):
            module.validate(record, self.reference, self.soname)

    def test_hardening_and_paths_rejected(self):
        for key, value in [('now', False), ('relro', False), ('textrel', True),
                           ('search_path', True), ('executable_stack', True),
                           ('writable_executable_load', True)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.validate(dict(self.reference, **{key: value}), self.reference, self.soname)

    def test_architecture_and_type_rejected(self):
        for key, value in [('class', 'ELF32'), ('machine', 'other architecture'),
                           ('osabi', 'other ABI'), ('type', 'EXEC'), ('soname', 'wrong.so')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.validate(dict(self.reference, **{key: value}), self.reference, self.soname)

    def test_parser_detects_dynamic_flags(self):
        altered = self.text + '\n0x0 (RUNPATH) Library runpath: [/tmp/builder]\n0x0 (TEXTREL) 0x0\n'
        parsed = module.parse(altered)
        self.assertTrue(parsed['search_path'])
        self.assertTrue(parsed['textrel'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--readelf', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    args, remaining = parser.parse_known_args()
    inspected = module.inspect(args.readelf.resolve(strict=True), args.reference.resolve(strict=True))
    SharedTest.reference = inspected['metadata']
    SharedTest.text = inspected['stdout']
    SharedTest.soname = inspected['metadata']['soname']
    unittest.main(argv=[sys.argv[0]] + remaining)
