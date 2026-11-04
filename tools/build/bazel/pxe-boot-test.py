# SPDX-License-Identifier: BSD-2-Clause
"""Inspect actual PXE composition and execute the real byte-transform CLI."""
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
for name in ['image', 'prefix', 'object', 'loader', 'client', 'source_client', 'archive', 'metadata', 'policy', 'helper']:
    parser.add_argument('--' + name.replace('_','-'), type=Path, required=True)
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining
policy = json.loads(args.policy.read_text())


class PxeImage(unittest.TestCase):
    def test_input_abi_and_loader_entry(self):
        data = args.object.read_bytes()
        self.assertEqual(data[:6], b'\x7fELF\x01\x01')
        self.assertEqual(struct.unpack_from('<HH', data, 16), (1,3))
        self.assertFalse(args.prefix.read_bytes().startswith(b'\x7fELF'))
        self.assertEqual(args.client.read_bytes(), args.source_client.read_bytes())
        self.assertLessEqual(args.client.stat().st_size, policy['maximum'])
        info,text,size,bss,syms,entry,tr,dr = struct.unpack_from('<8I', args.loader.read_bytes())
        self.assertEqual((info & 0xffff, (info>>16)&0xff), (0x10b,0x86))
        self.assertEqual(entry, policy['address'])
        self.assertEqual((bss,syms,tr,dr), (0,0,0,0))
        self.assertEqual(args.loader.stat().st_size,4096+text+size)

    def test_complete_prefix_loader_and_sector_padding(self):
        payload = args.prefix.read_bytes() + args.loader.read_bytes()
        self.assertEqual(args.image.read_bytes(), payload + bytes((-len(payload)) % 2048))
        self.assertEqual(args.image.stat().st_size % 2048, 0)

    def test_archive_and_package_metadata(self):
        image = '/boot/pxeboot'
        manual = '/usr/share/man/man8/pxeboot.8' + ('.gz' if policy['compressed'] else '')
        records = {r['destination']:r for r in json.loads(args.metadata.read_text())['files']}
        self.assertEqual(set(records), {image} | ({manual} if policy['man'] else set()))
        for path,r in records.items():
            self.assertEqual((r['type'],r['owner'],r['group'],r['mode']), ('file','root','wheel','0444'))
            package = 'bootloader-man' if path==manual and policy['split'] else 'bootloader'
            self.assertEqual(r['tags'], ['package='+package])
        with tarfile.open(args.archive) as archive:
            files = {m.name:m for m in archive.getmembers() if not m.isdir()}
            self.assertEqual(set(files), {p.lstrip('/') for p in records})
            for m in files.values():
                self.assertTrue(m.isfile())
                self.assertEqual((m.uid,m.gid,m.mode), (0,0,0o444))
            self.assertEqual(archive.extractfile(files['boot/pxeboot']).read(), args.image.read_bytes())
            if policy['man']:
                self.assertEqual(archive.extractfile(files[manual.lstrip('/')]).read().startswith(b'\x1f\x8b'),policy['compressed'])

    def test_actual_size_guard_and_dd_alignment_boundaries(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temp:
            out = Path(temp)/'result'
            command = [sys.executable,'-B',str(args.helper),'--output',str(out)]
            size = args.client.stat().st_size
            for maximum,success in [(size,True),(size-1,False)]:
                run = subprocess.run(command+['--operation','check','--size',str(maximum),str(args.client)],capture_output=True,text=True,timeout=30)
                self.assertEqual(run.returncode==0,success,run.stderr)
                if not success:self.assertIn('exceeds its declared size limit',run.stderr)
                self.assertEqual(out.read_bytes(),args.client.read_bytes())
            source = Path(temp)/'block'
            for size in [0,1,2047,2048,2049,4096]:
                data = bytes([0x5a])*size
                source.write_bytes(data)
                run = subprocess.run(command+['--operation','align','--size','2048',str(source)],capture_output=True,text=True,timeout=30)
                self.assertEqual(run.returncode,0,run.stderr)
                self.assertEqual(out.read_bytes(),data+bytes((-size)%2048))


if __name__=='__main__':
    unittest.main()
