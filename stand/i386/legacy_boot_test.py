#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check real generated BIOS/BTX format and input ABI; never execute an image."""
import os
from pathlib import Path
import struct
import unittest

ROOT = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE'] / 'stand/i386'
COMPONENTS = {'boot0': 'boot0', 'boot0sio': 'boot0', 'mbr': 'mbr', 'pmbr': 'pmbr',
              'cdboot': 'cdboot', 'btx/btx': 'btx', 'btx/btxldr': 'btxldr'}


def image(component):
    return (ROOT / component / component.rsplit('/', 1)[-1]).read_bytes()


def check_object(data):
    if len(data) < 52 or data[:7] != b'\x7fELF\x01\x01\x01':
        raise ValueError('i386 ELF32 little-endian object required')
    if struct.unpack_from('<HH', data, 16) != (1, 3):
        raise ValueError('relocatable i386 object required')


def check_mbr(data):
    if len(data) != 512 or data[510:] != b'\x55\xaa':
        raise ValueError('512-byte boot template with BIOS signature required')
    if data[446:510] != bytes(64):
        raise ValueError('unpopulated partition-table template required')


def check_btx(data):
    if len(data) < 16 or data[2:5] != b'BTX' or data[0] != 0xeb or data[1] != 14:
        raise ValueError('BTX header required')
    if struct.unpack_from('<H', data, 10)[0] != len(data):
        raise ValueError('BTX text extent must match the generated image')


class GeneratedArtifacts(unittest.TestCase):
    def test_input_objects_are_i386(self):
        for component, name in COMPONENTS.items():
            with self.subTest(component=component):
                check_object((ROOT / component / (name + '.o')).read_bytes())

    def test_mbr_templates(self):
        for name in ['boot0', 'boot0sio', 'mbr', 'pmbr']:
            with self.subTest(component=name):
                check_mbr(image(name))

    def test_btx_header(self):
        check_btx(image('btx/btx'))

    def test_serial_console_is_a_distinct_variant(self):
        self.assertNotEqual(image('boot0'), image('boot0sio'))

    def test_flat_loader_artifacts(self):
        for component in ['cdboot', 'btx/btxldr']:
            with self.subTest(component=component):
                data = image(component)
                self.assertTrue(data)
                self.assertFalse(data.startswith(b'\x7fELF'))

    def test_wrong_abi_rejected(self):
        data = bytearray((ROOT / 'boot0/boot0.o').read_bytes())
        data[4] = 2
        with self.assertRaises(ValueError):
            check_object(data)

    def test_corrupt_formats_rejected(self):
        data = bytearray(image('mbr'))
        data[510] ^= 1
        with self.assertRaises(ValueError):
            check_mbr(data)
        data = bytearray(image('btx/btx'))
        struct.pack_into('<H', data, 10, len(data) - 1)
        with self.assertRaises(ValueError):
            check_btx(data)


if __name__ == '__main__':
    unittest.main()
