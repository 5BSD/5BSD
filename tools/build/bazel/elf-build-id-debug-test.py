# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Exercise binary/debug build-ID binding with real, CRC-consistent mutations."""
import argparse
import importlib.util
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib

parser = argparse.ArgumentParser()
for name in ('binary', 'debug'):
    parser.add_argument('--' + name, type=Path, required=True)
parser.add_argument('--checker', type=Path, default=Path(__file__).with_name('elf-debug-check.py'))
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining
root = Path(os.environ.get('TEST_SRCDIR', '/'))
for name in ('binary', 'debug'):
    setattr(args, name, (root / getattr(args, name)).resolve(strict=True))
spec = importlib.util.spec_from_file_location('debug_check', args.checker)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def section(data, name):
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('ELF64 little-endian fixture required')
    h = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    entries = [(h[5] + i * h[10], struct.unpack_from('<IIQQQQIIQQ', data, h[5] + i * h[10]))
               for i in range(h[11])]
    strings = entries[h[12]][1]
    names = data[strings[4]:strings[4] + strings[5]]
    found = [(at, e) for at, e in entries if names[e[0]:names.index(0, e[0])].decode() == name]
    if len(found) != 1:
        raise ValueError('unique fixture section required: ' + name)
    at, e = found[0]
    return at, e[4], e[5]


class DebugBuildIdentity(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.binary = Path(self.directory.name) / args.binary.name
        self.debug = Path(self.directory.name) / args.debug.name
        self.runtime = bytearray(args.binary.read_bytes())
        self.symbols = bytearray(args.debug.read_bytes())

    def verify(self, repair_crc=False):
        if repair_crc:
            _, start, size = section(self.runtime, '.gnu_debuglink')
            link = self.runtime[start:start + size]
            offset = (link.index(0) + 4) & ~3
            struct.pack_into('<I', self.runtime, start + offset, zlib.crc32(self.symbols))
        self.binary.write_bytes(self.runtime)
        self.debug.write_bytes(self.symbols)
        return checker.verify(self.binary, self.debug, module=True)

    def test_actual_pair(self):
        result = self.verify()
        self.assertEqual(result['status'], 'passed')
        self.assertTrue(result['build_id'])

    def test_different_debug_identity_with_repaired_crc(self):
        _, at, _ = section(self.symbols, '.note.gnu.build-id')
        self.symbols[at + 16] ^= 1
        with self.assertRaisesRegex(ValueError, 'build IDs differ'):
            self.verify(repair_crc=True)

    def test_debug_note_missing_with_repaired_crc(self):
        at, _, _ = section(self.symbols, '.note.gnu.build-id')
        struct.pack_into('<I', self.symbols, at, 0)
        with self.assertRaisesRegex(ValueError, 'build-ID presence differs'):
            self.verify(repair_crc=True)

    def test_runtime_note_missing(self):
        at, _, _ = section(self.runtime, '.note.gnu.build-id')
        struct.pack_into('<I', self.runtime, at, 0)
        with self.assertRaisesRegex(ValueError, 'build-ID presence differs'):
            self.verify()

    def test_invalid_note_kind_with_repaired_crc(self):
        _, at, _ = section(self.symbols, '.note.gnu.build-id')
        struct.pack_into('<I', self.symbols, at + 8, 99)
        with self.assertRaisesRegex(ValueError, 'invalid GNU build-ID note'):
            self.verify(repair_crc=True)

    def test_invalid_note_length_with_repaired_crc(self):
        _, at, _ = section(self.symbols, '.note.gnu.build-id')
        struct.pack_into('<I', self.symbols, at + 4, 0)
        with self.assertRaisesRegex(ValueError, 'invalid GNU build-ID note'):
            self.verify(repair_crc=True)

    def test_wrong_section_kind_with_repaired_crc(self):
        at, _, _ = section(self.symbols, '.note.gnu.build-id')
        struct.pack_into('<I', self.symbols, at + 4, 1)
        with self.assertRaisesRegex(ValueError, 'GNU build-ID section must be a note'):
            self.verify(repair_crc=True)


if __name__ == '__main__':
    unittest.main()
