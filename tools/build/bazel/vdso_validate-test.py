#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Independent synthetic ELF policies and real command-output failure checks."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import vdso_validate

POLICY = dict(machine=62, osabi=9, maximum_size=2048,
              symbol='__vdso_sigcode', soname='elf-vdso.so.1')


def fixture(extra_tags=()):
    """Small artificial ELF with explicit table/segment layout, never executed."""
    b = bytearray(1024)
    b[:16] = b'\x7fELF\x02\x01\x01\x09' + bytes(8)
    struct.pack_into('<HHIQQQIHHHHHH', b, 16, 3, 62, 1, 0, 64, 640, 0,
                     64, 56, 2, 64, 6, 4)
    names = b'\0__vdso_sigcode\0elf-vdso.so.1\0'
    tags = [(5, 432), (10, len(names)), (6, 336), (11, 24),
            (14, names.index(b'elf-vdso')), *extra_tags, (0, 0)]
    assert 176 + len(tags) * 16 <= 336
    struct.pack_into('<IIQQQQQQ', b, 64, 1, 5, 0, 0, 0, 512, 512, 16)
    struct.pack_into('<IIQQQQQQ', b, 120, 2, 5, 176, 176, 176,
                     len(tags) * 16, len(tags) * 16, 8)
    for i, item in enumerate(tags):
        struct.pack_into('<qQ', b, 176 + i * 16, *item)
    struct.pack_into('<IBBHQQ', b, 360, 1, 0x12, 0, 3, 480, 8)
    b[432:432 + len(names)] = names
    b[480:488] = b'\xc3' * 8
    # null, dynsym, dynstr, code, section-name strings, dynamic
    rows = [(0,) * 10,
            (0, 11, 2, 336, 336, 48, 2, 1, 8, 24),
            (0, 3, 2, 432, 432, len(names), 0, 0, 1, 0),
            (0, 1, 6, 480, 480, 8, 0, 0, 16, 0),
            (0, 3, 0, 0, 512, 1, 0, 0, 1, 0),
            (0, 6, 2, 176, 176, len(tags) * 16, 2, 0, 8, 16)]
    for i, row in enumerate(rows):
        struct.pack_into('<IIQQQQIIQQ', b, 640 + i * 64, *row)
    return b


class VdsoTests(unittest.TestCase):
    def check(self, blob, **changes):
        return vdso_validate.inspect(blob, **(POLICY | changes))

    def reject(self, blob, **changes):
        with self.assertRaises(ValueError):
            self.check(blob, **changes)

    def test_valid_image(self):
        self.assertEqual(self.check(fixture()), 480)

    def test_target_machine_is_input(self):
        b = fixture(); struct.pack_into('<H', b, 18, 183)
        self.reject(b)
        self.assertEqual(self.check(b, machine=183), 480)

    def test_size_policy_is_input(self):
        self.assertEqual(self.check(fixture(), maximum_size=1024), 480)
        self.reject(fixture(), maximum_size=1023)
        self.reject(fixture(), maximum_size=0)

    def test_elf_identity(self):
        for offset, value in [(0, 0), (4, 1), (5, 2), (6, 0), (7, 0)]:
            with self.subTest(offset=offset):
                b = fixture(); b[offset] = value; self.reject(b)

    def test_truncated_and_bad_tables(self):
        for length in [0, 63, 128, 700, 1023]:
            with self.subTest(length=length):
                self.reject(fixture()[:length])
        for offset, fmt, value in [(32, '<Q', 1000), (40, '<Q', 1000),
                                   (54, '<H', 55), (58, '<H', 63), (60, '<H', 0)]:
            with self.subTest(offset=offset):
                b = fixture(); struct.pack_into(fmt, b, offset, value); self.reject(b)

    def test_shared_header(self):
        for offset, fmt, value in [(16, '<H', 2), (20, '<I', 0),
                                   (24, '<Q', 480), (48, '<I', 1)]:
            b = fixture(); struct.pack_into(fmt, b, offset, value); self.reject(b)

    def test_load_mapping_and_permissions(self):
        for offset, fmt, value in [(68, '<I', 7), (80, '<Q', 1),
                                   (104, '<Q', 513), (96, '<Q', 2000)]:
            b = fixture(); struct.pack_into(fmt, b, offset, value); self.reject(b)

    def test_extra_loader_segments(self):
        for kind in [1, 3, 7]:
            b = fixture(); struct.pack_into('<I', b, 120, kind); self.reject(b)

    def test_dynamic_table_shape(self):
        for offset, fmt, value in [(124, '<I', 7), (128, '<Q', 1000),
                                   (152, '<Q', 95), (160, '<Q', 95)]:
            b = fixture(); struct.pack_into(fmt, b, offset, value); self.reject(b)
        b = fixture(); struct.pack_into('<qQ', b, 256, 24, 0); self.reject(b)
        self.reject(fixture([(5, 432)]))

    def test_runtime_relocations(self):
        for tag in [2, 8, 18, 35, 0x6ffffff9, 0x6ffffffa]:
            with self.subTest(tag=tag):
                self.reject(fixture([(tag, 1)]))
                self.assertEqual(self.check(fixture([(tag, 0)])), 480)
        self.reject(fixture([(22, 0)]))
        self.reject(fixture([(30, 4)]))

    def test_external_dependencies(self):
        self.reject(fixture([(1, 15)]))

    def test_relocation_and_nobits_sections(self):
        for kind in [4, 8, 9, 19]:
            b = fixture(); struct.pack_into('<I', b, 640 + 4 * 64 + 4, kind)
            self.reject(b)

    def test_metadata_pointers_and_bounds(self):
        b = fixture(); struct.pack_into('<Q', b, 184, 433); self.reject(b)
        b = fixture(); struct.pack_into('<Q', b, 640 + 2 * 64 + 24, 1020); self.reject(b)
        b = fixture(); struct.pack_into('<Q', b, 640 + 1 * 64 + 8, 0); self.reject(b)
        b = fixture(); struct.pack_into('<Q', b, 640 + 5 * 64 + 32, 80); self.reject(b)
        b = fixture(); struct.pack_into('<I', b, 640 + 1 * 64 + 40, 6); self.reject(b)

    def test_symbol_contract(self):
        for offset, fmt, value in [(360, '<I', 15), (364, '<B', 0x11),
                                   (365, '<B', 2), (366, '<H', 0),
                                   (368, '<Q', 488), (376, '<Q', 9)]:
            b = fixture(); struct.pack_into(fmt, b, offset, value); self.reject(b)
        b = fixture(); struct.pack_into('<Q', b, 640 + 3 * 64 + 8, 4); self.reject(b)
        b = fixture(); b[384:408] = b[360:384]
        struct.pack_into('<Q', b, 640 + 1 * 64 + 32, 72); self.reject(b)

    def test_soname_and_strings(self):
        self.reject(fixture(), soname='other.so')
        self.reject(fixture(), symbol='__other_entry')
        b = fixture(); b[460] = 1; self.reject(b)

    def test_command_outputs_and_rejection(self):
        script = Path(vdso_validate.__file__)
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory); src = d / 'source'; image = d / 'image'; header = d / 'header'
            argv = [sys.executable, '-B', str(script), '--src', str(src),
                    '--image', str(image), '--header', str(header), '--machine', '62',
                    '--osabi', '9', '--maximum-size', '2048', '--symbol', '__vdso_sigcode',
                    '--macro', 'VDSO_SIGCODE_OFFSET', '--soname', 'elf-vdso.so.1']
            src.write_bytes(fixture())
            result = subprocess.run(argv, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(image.read_bytes(), src.read_bytes())
            self.assertEqual(header.read_text(), '#define VDSO_SIGCODE_OFFSET 0x00000000000001e0\n')
            image.unlink(); header.unlink(); src.write_bytes(b'bad')
            result = subprocess.run(argv, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(image.exists()); self.assertFalse(header.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
