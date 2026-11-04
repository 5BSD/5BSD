# SPDX-License-Identifier: BSD-2-Clause
"""Inspect the actual IA32 loader artifacts; does not execute firmware."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

parser = argparse.ArgumentParser()
for name in ['image', 'full', 'manifest', 'nm']:
    parser.add_argument('--' + name, type=Path, required=True)
parser.add_argument('--nm-inputs', type=Path, nargs='+', required=True)
parser.add_argument('--epoch-file', type=Path, required=True)
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining


class Ia32Loader(unittest.TestCase):
    def test_firmware_image_abi(self):
        data = args.image.read_bytes()
        self.assertEqual(data[:2], b'MZ')
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        self.assertEqual(data[pe:pe + 4], b'PE\0\0')
        machine, count, epoch = struct.unpack_from('<HHI', data, pe + 4)
        self.assertEqual(machine, 0x14c)
        self.assertGreater(count, 0)
        self.assertEqual(epoch, int(args.epoch_file.read_text()))
        optional = pe + 24
        self.assertEqual(struct.unpack_from('<H', data, optional)[0], 0x10b)
        self.assertEqual(struct.unpack_from('<H', data, optional + 68)[0], 10)
        entry = struct.unpack_from('<I', data, optional + 16)[0]
        image_size = struct.unpack_from('<I', data, optional + 56)[0]
        self.assertGreater(entry, 0)
        self.assertLess(entry, image_size)
        self.assertEqual(struct.unpack_from('<II', data, optional + 104), (0, 0),
                         'EFI must not depend on a hosted PE import table')

    def test_full_link_abi_and_symbols(self):
        data = args.full.read_bytes()
        self.assertEqual(data[:6], b'\x7fELF\x01\x01')
        self.assertEqual(struct.unpack_from('<HH', data, 16), (3, 3))
        runtime = [p for p in args.nm_inputs if p.resolve() != args.nm.resolve()]
        env = {'LC_ALL': 'C', 'LD_LIBRARY_PATH': ':'.join(sorted({str(p.resolve(strict=True).parent) for p in runtime}))}
        result = subprocess.run([str(args.nm), '--format=posix', str(args.full)],
                                capture_output=True, text=True, env=env, check=True, timeout=30)
        symbols = {fields[0]: fields[1] for line in result.stdout.splitlines()
                   if len(fields := line.split()) >= 2}
        self.assertNotIn('U', symbols.values())
        for name in ['_start', 'setup', 'amd64_tramp', 'efi_main', 'lua_newstate',
                     'verify_required', 'verity_check_source']:
            self.assertIn(name, symbols)
        self.assertNotIn('__stack_chk_fail', symbols)

    def test_ia32_installation_contribution(self):
        manifest = json.loads(args.manifest.read_text())
        self.assertEqual(manifest['format'], 1)
        self.assertEqual(len(manifest['files']), 1)
        record = manifest['files'][0]
        self.assertEqual(record['destination'], '/boot/loader_ia32.efi')
        self.assertEqual((record['type'], record['owner'], record['group'], record['mode']),
                         ('file', 'root', 'wheel', '0555'))
        self.assertEqual(record['tags'], ['package=bootloader'])


if __name__ == '__main__':
    unittest.main()
