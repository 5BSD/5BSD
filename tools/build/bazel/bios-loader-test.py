# SPDX-License-Identifier: BSD-2-Clause
"""Inspect the complete BIOS loader and exercise the real guarded strip action."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tarfile
import unittest

parser = argparse.ArgumentParser()
for name in ['archive','image','symbols','client','stub','kernel','metadata','policy','helper','strip']:
    parser.add_argument('--'+name, type=Path, required=True)
parser.add_argument('--strip-inputs', type=Path, nargs='+', required=True)
parser.add_argument('--objects', type=Path, nargs='+', required=True)
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining
policy = json.loads(args.policy.read_text())


def elf(data):
    if data[:6] != b'\x7fELF\x01\x01':
        raise ValueError('ELF32 little-endian image required')
    return struct.unpack_from('<16sHHIIIIIHHHHHH',data)


class BiosLoader(unittest.TestCase):
    def test_real_entry_objects_and_static_link(self):
        self.assertEqual(len(args.objects),36)
        for p in args.objects:
            with self.subTest(path=p):
                self.assertEqual(elf(p.read_bytes())[1:3],(1,3))
        for p in [args.symbols,args.client]:
            data=p.read_bytes();h=elf(data)
            self.assertEqual(h[1:3],(2,3))
            self.assertEqual(h[4],0)
            kinds=[struct.unpack_from('<I',data,h[5]+i*h[9])[0] for i in range(h[10])]
            self.assertNotIn(3,kinds,'no hosted interpreter in BIOS client')
        self.assertLessEqual(args.client.stat().st_size,policy['maximum'])

    def test_complete_aout_btx_and_client_layout(self):
        data=args.image.read_bytes();info,text,size,bss,syms,entry,tr,dr=struct.unpack_from('<8I',data)
        self.assertEqual((info&0xffff,(info>>16)&0xff),(0x10b,0x86))
        self.assertEqual(entry,policy['address'])
        self.assertEqual((bss,syms,tr,dr),(0,0,0,0))
        self.assertEqual(len(data),4096+text+size)
        self.assertEqual(text%4096,0)
        stub=args.stub.read_bytes();kernel=args.kernel.read_bytes();client=args.client.read_bytes()
        self.assertEqual(data[4096:4096+len(stub)],stub)
        base=4096+text
        self.assertEqual(data[base+2:base+5],b'BTX')
        extent=struct.unpack_from('<H',data,base+10)[0]
        self.assertEqual(extent,len(kernel))
        self.assertEqual(data[base+16:base+extent],kernel[16:])
        self.assertEqual(struct.unpack_from('<I',data,base+12)[0],elf(client)[4])
        self.assertEqual(data[base+extent:base+extent+len(client)],client)

    def test_static_client_has_no_inherited_startup_debug_link(self):
        data=args.client.read_bytes();h=elf(data)
        table=[struct.unpack_from('<IIIIIIIIII',data,h[6]+i*h[11]) for i in range(h[12])]
        strings=table[h[13]];names=data[strings[4]:strings[4]+strings[5]]
        section_names={names[s[0]:names.index(b'\0',s[0])].decode() for s in table}
        self.assertNotIn('.gnu_debuglink',section_names)

    def test_installed_default_and_zfs_links(self):
        records={r['destination']:r for r in json.loads(args.metadata.read_text())['files']}
        self.assertEqual(set(records),{'/boot/loader_lua','/boot/loader','/boot/zfsloader'})
        self.assertEqual(records['/boot/loader_lua']['type'],'file')
        for name,r in records.items():
            self.assertEqual((r['owner'],r['group'],r['mode']),('root','wheel','0555'))
            self.assertEqual(r['tags'],['package=bootloader'])
            if name!='/boot/loader_lua':
                self.assertEqual((r['type'],r['link']),('hardlink','/boot/loader_lua'))

    def test_real_installation_archive_and_hardlink_inodes(self):
        with tarfile.open(args.archive) as archive:
            members=archive.getmembers()
            for member in members:
                self.assertFalse(Path(member.name).is_absolute())
                self.assertNotIn('..',Path(member.name).parts)
            files={m.name:m for m in members if not m.isdir()}
            self.assertEqual(set(files),{'boot/loader_lua','boot/loader','boot/zfsloader'})
            self.assertTrue(files['boot/loader_lua'].isfile())
            self.assertEqual(archive.extractfile(files['boot/loader_lua']).read(),args.image.read_bytes())
            for name,member in files.items():
                self.assertEqual((member.uid,member.gid,member.mode),(0,0,0o555))
                if name!='boot/loader_lua':
                    self.assertTrue(member.islnk())
                    self.assertEqual(member.linkname,'boot/loader_lua')
            with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temp:
                # This build-owned archive has validated paths/types/link targets above.
                # Preserve its modes: data_filter deliberately adds owner write permission.
                archive.extractall(temp,filter='fully_trusted')
                stats=[(Path(temp)/name).stat() for name in files]
                self.assertEqual(len({(s.st_dev,s.st_ino) for s in stats}),1)
                self.assertTrue(all(s.st_mode&0o7777==0o555 for s in stats))

    def test_actual_strip_exact_limit_and_overflow_are_atomic(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temp:
            output=Path(temp)/'guarded-client'
            command=[sys.executable,'-B','-S',str(args.helper),'--source',str(args.symbols),
                     '--output',str(output),'--strip',str(args.strip)]
            tail=['--runtime',*[str(p) for p in args.strip_inputs]]
            size=args.client.stat().st_size
            result=subprocess.run(command+['--max-size',str(size)]+tail,capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(output.read_bytes(),args.client.read_bytes())
            before=output.read_bytes()
            result=subprocess.run(command+['--max-size',str(size-1)]+tail,capture_output=True,text=True,timeout=30)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('exceeds its declared size limit',result.stderr)
            self.assertEqual(output.read_bytes(),before)
            self.assertEqual(list(Path(temp).iterdir()),[output])


if __name__=='__main__':
    unittest.main()
