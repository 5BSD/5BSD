# SPDX-License-Identifier: BSD-2-Clause
"""Inspect real GPT/UFS, ISO and GPT/ZFS boot artifacts and exercise the actual size-check CLI."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

parser = argparse.ArgumentParser()
for name in ['helper', 'policy', 'kernel']:
    parser.add_argument('--' + name, type=Path, required=True)
parser.add_argument('--components', nargs='+', choices=['gptboot', 'isoboot', 'gptzfsboot'],
                    default=['gptboot', 'isoboot'])
selected, _ = parser.parse_known_args()
if len(set(selected.components)) != len(selected.components):
    parser.error('distinct boot components required')
for name in selected.components:
    for target in [name, 'client', 'symbols', 'loader', 'loader_elf', 'install_archive']:
        parser.add_argument('--' + name + '-' + target, type=Path, required=True)
    parser.add_argument('--' + name + '-objects', type=Path, nargs='+', required=True)
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining
policy = json.loads(args.policy.read_text())


def artifact(component, target):
    return getattr(args, component + '_' + target)


def elf(data):
    if data[:6] != b'\x7fELF\x01\x01':
        raise ValueError('ELF32 little-endian image required')
    return struct.unpack_from('<16sHHIIIIIHHHHHH', data)


class BootImages(unittest.TestCase):
    def test_input_and_linked_abi(self):
        for component in args.components:
            objects = artifact(component, 'objects')
            expected = ({'zfsboot.o', 'sio.o', 'cons.o', 'bcache.o', 'devopen.o', 'disk.o', 'part.o', 'zfs_cmd.o', 'misc.o', 'gptldr.o'}
                        if component == 'gptzfsboot' else {component + '.o', 'cons.o', 'drv.o', 'sio.o', 'gptldr.o'})
            self.assertEqual({p.name for p in objects}, expected)
            for obj in objects:
                self.assertEqual(elf(obj.read_bytes())[1:3], (1, 3))
            for name, entry in [('symbols', 0), ('loader_elf', 0x7c00)]:
                data = artifact(component, name).read_bytes()
                h = elf(data)
                self.assertEqual(h[1:3], (2, 3))
                self.assertEqual(h[4], entry)
                self.assertNotIn(3, [struct.unpack_from('<I', data, h[5] + i*h[9])[0] for i in range(h[10])])

    def test_complete_btx_and_client_layout(self):
        kernel = args.kernel.read_bytes()
        for component in args.components:
            data = artifact(component, component).read_bytes()
            loader = artifact(component, 'loader').read_bytes()
            client = artifact(component, 'client').read_bytes()
            self.assertEqual(data[:len(loader)], loader)
            btx = data[len(loader):len(loader) + len(kernel)]
            self.assertEqual(btx[2:5], b'BTX')
            self.assertEqual(struct.unpack_from('<H', btx, 10)[0], len(kernel))
            self.assertEqual(struct.unpack_from('<I', btx, 12)[0], 0)
            self.assertEqual(btx[16:], kernel[16:])
            self.assertEqual(data[len(loader) + len(kernel):], client)
            self.assertFalse(client.startswith(b'\x7fELF'))
        if 'isoboot' in args.components:
            self.assertLessEqual(artifact('isoboot', 'isoboot').stat().st_size, policy['maximum'])

    def test_real_archives(self):
        for component in args.components:
            with tarfile.open(artifact(component, 'install_archive')) as archive:
                files = {m.name: m for m in archive.getmembers() if not m.isdir()}
                image = 'boot/' + component
                manual = 'usr/share/man/man8/' + component + '.8' + ('.gz' if policy['compressed'] else '')
                self.assertEqual(set(files), {image} | ({manual} if policy['man'] else set()))
                for member in files.values():
                    self.assertTrue(member.isfile())
                    self.assertEqual((member.uid, member.gid, member.mode), (0, 0, 0o444))
                self.assertEqual(archive.extractfile(files[image]).read(), artifact(component, component).read_bytes())
                if policy['man']:
                    self.assertEqual(archive.extractfile(files[manual]).read().startswith(b'\x1f\x8b'), policy['compressed'])

    def test_actual_size_boundary_preserves_previous_output_on_failure(self):
        if 'isoboot' not in args.components:
            self.skipTest('the bounded ISO artifact is not selected')
        source = artifact('isoboot', 'isoboot')
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temp:
            output = Path(temp) / 'checked'
            command = [sys.executable, '-B', str(args.helper), '--operation', 'check', '--output', str(output)]
            run = subprocess.run(command + ['--size', str(source.stat().st_size), str(source)], capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(output.read_bytes(), source.read_bytes())
            run = subprocess.run(command + ['--size', str(source.stat().st_size - 1), str(source)], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('exceeds its declared size limit', run.stderr)
            self.assertEqual(output.read_bytes(), source.read_bytes())


if __name__ == '__main__':
    unittest.main()
