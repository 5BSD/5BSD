# SPDX-License-Identifier: BSD-2-Clause
"""Inspect the actual Linux-hosted loader; never execute its Linux syscalls here."""
import argparse
import json
from pathlib import Path
import struct
import sys
import tarfile
import unittest

parser = argparse.ArgumentParser()
for name in ['image', 'symbols', 'help-data', 'manifest', 'archive']:
    parser.add_argument('--' + name, type=Path, required=True)
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining


def elf(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('ELF64 little-endian image required')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    segments = [struct.unpack_from('<IIQQQQQQ', data, header[5] + i * header[9])
                for i in range(header[10])]
    return header, segments


class KbootLoader(unittest.TestCase):
    def test_static_amd64_entry_and_installed_image(self):
        for path in [args.symbols, args.image]:
            with self.subTest(path=path.name):
                header, segments = elf(path.read_bytes())
                self.assertEqual(header[1:3], (2, 62))
                self.assertNotIn(3, [s[0] for s in segments], 'unexpected PT_INTERP')
                self.assertNotIn(2, [s[0] for s in segments], 'unexpected PT_DYNAMIC')
                self.assertTrue(any(s[0] == 1 and s[1] & 1 and s[3] <= header[4] < s[3] + s[6]
                                    for s in segments), 'entry not in executable PT_LOAD')
        original, _ = elf(args.symbols.read_bytes())
        installed, _ = elf(args.image.read_bytes())
        self.assertEqual(original[4], installed[4])
        self.assertLessEqual(args.image.stat().st_size, args.symbols.stat().st_size)

    def test_exact_installation_metadata(self):
        records = json.loads(args.manifest.read_text())['files']
        self.assertEqual(len(records), 2)
        expected = {'/boot/loader.kboot': '0555', '/boot/loader.help.kboot': '0444'}
        self.assertEqual({r['destination'] for r in records}, set(expected))
        for record in records:
            self.assertEqual(record['mode'], expected[record['destination']])
            self.assertEqual((record['type'], record['owner'], record['group']), ('file', 'root', 'wheel'))
            self.assertEqual(record['tags'], ['package=bootloader'])

    def test_real_archive_payload_and_permissions(self):
        expected = {'boot/loader.kboot': (args.image, 0o555),
                    'boot/loader.help.kboot': (args.help_data, 0o444)}
        with tarfile.open(args.archive) as archive:
            files = {m.name.removeprefix('./'): m for m in archive.getmembers() if not m.isdir()}
            self.assertEqual(set(files), set(expected))
            for name, (source, mode) in expected.items():
                member = files[name]
                self.assertTrue(member.isfile())
                self.assertEqual((member.uid, member.gid, member.mode), (0, 0, mode))
                self.assertEqual(archive.extractfile(member).read(), source.read_bytes())
        self.assertIn(b'boot', args.help_data.read_bytes())


if __name__ == '__main__':
    unittest.main()
