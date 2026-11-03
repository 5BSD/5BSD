# SPDX-License-Identifier: BSD-2-Clause
"""Inspect generated boot images as data. No target image is executed."""
import importlib.util
import os
from pathlib import Path
import re
import struct
import unittest

ROOT = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
BOOT = ROOT / 'stand/i386/boot2'
SPEC = importlib.util.spec_from_file_location('boot_image', ROOT / 'tools/build/bazel/boot_image.py')
IMAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMAGE)


class BootChain(unittest.TestCase):
    def test_installed_image_extent_and_order(self):
        first = (BOOT / 'boot1').read_bytes()
        second = (BOOT / 'boot2').read_bytes()
        self.assertEqual(len(first), 512)
        self.assertEqual(first[510:], b'\x55\xaa')
        self.assertEqual(len(second), 7680)
        self.assertEqual((BOOT / 'boot').read_bytes(), first + second)

    def test_btx_image_padding(self):
        linked = (BOOT / 'boot2.ld').read_bytes()
        self.assertLessEqual(len(linked), 7680)
        self.assertEqual((BOOT / 'boot2').read_bytes(), linked + bytes(7680 - len(linked)))
        self.assertEqual((BOOT / 'boot2.ldr').read_bytes(), bytes(512))
        self.assertEqual(linked[:512], bytes(512))
        self.assertEqual(linked[514:517], b'BTX')
        self.assertEqual(struct.unpack_from('<I', linked, 524)[0], 0x2000)

    def test_generated_xread_header(self):
        symbols = (BOOT / 'boot1.nm').read_text().splitlines()
        matches = [int(line.split()[0]) for line in symbols if re.search(r'([0-9])+ T xread', line)]
        self.assertEqual(len(matches), 1)
        expected = '#define XREADORG %#x\n' % (1792 + matches[0] - 31744)
        self.assertEqual((BOOT / 'boot2.h').read_text(), expected)

    def test_btx_startup_object_abi(self):
        data = (ROOT / 'stand/i386/btx/lib/crt0.o').read_bytes()
        self.assertEqual(data[:7], b'\x7fELF\x01\x01\x01')
        self.assertEqual(struct.unpack_from('<HH', data, 16), (1, 3))

    def test_size_limit_rejects_overflow(self):
        with self.assertRaisesRegex(ValueError, 'exceeds'):
            IMAGE.image_bytes('pad', [bytes(7681)], 7680)
        self.assertEqual(IMAGE.image_bytes('pad', [bytes(7680)], 7680), bytes(7680))

    def test_invalid_image_operations_rejected(self):
        for operation, sources, size in [('zero', [b'x'], 512), ('zero', [], 0),
                                         ('pad', [], 512), ('pad', [b'a'], -1),
                                         ('concat', [b'a'], 0), ('concat', [b'a', b'b'], 1)]:
            with self.subTest(operation=operation, size=size), self.assertRaises(ValueError):
                IMAGE.image_bytes(operation, sources, size)
        self.assertEqual(IMAGE.image_bytes('concat', [b'a', b'b'], 0), b'ab')


if __name__ == '__main__':
    unittest.main()
