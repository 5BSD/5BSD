#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual archive flag serialization and rejection of dropped flags."""
import argparse
import ctypes as C
import os
import sys
import hashlib
from pathlib import Path
import stat
import tempfile
import unittest
import archive_headers
from install_archive import write_archive

parser=argparse.ArgumentParser(add_help=False)
parser.add_argument('--library',type=Path)
args,remaining=parser.parse_known_args()
sys.argv=[sys.argv[0],*remaining]
LIBRARY=args.library or archive_headers.LIBRARY
if not LIBRARY.is_absolute():LIBRARY=Path(os.environ['TEST_SRCDIR'])/LIBRARY
LIBRARY=LIBRARY.resolve(strict=True)


class ArchiveFlags(unittest.TestCase):
    def test_real_pax_header_flags(self):
        lib=C.CDLL(str(LIBRARY))
        def bind(name,args,result):
            fn=getattr(lib,name);fn.argtypes=args;fn.restype=result;return fn
        new=bind('archive_write_new',[],C.c_void_p)
        fmt=bind('archive_write_set_format_pax_restricted',[C.c_void_p],C.c_int)
        opened=bind('archive_write_open_filename',[C.c_void_p,C.c_char_p],C.c_int)
        header=bind('archive_write_header',[C.c_void_p,C.c_void_p],C.c_int)
        close=bind('archive_write_close',[C.c_void_p],C.c_int)
        free=bind('archive_write_free',[C.c_void_p],C.c_int)
        entry_new=bind('archive_entry_new',[],C.c_void_p)
        entry_free=bind('archive_entry_free',[C.c_void_p],None)
        path=bind('archive_entry_set_pathname',[C.c_void_p,C.c_char_p],None)
        mode=bind('archive_entry_set_mode',[C.c_void_p,C.c_uint],None)
        size=bind('archive_entry_set_size',[C.c_void_p,C.c_int64],None)
        uid=bind('archive_entry_set_uid',[C.c_void_p,C.c_int64],None)
        gid=bind('archive_entry_set_gid',[C.c_void_p,C.c_int64],None)
        mtime=bind('archive_entry_set_mtime',[C.c_void_p,C.c_int64,C.c_long],None)
        flags=bind('archive_entry_copy_fflags_text',[C.c_void_p,C.c_char_p],C.c_char_p)
        with tempfile.TemporaryDirectory() as tmp:
            archive=Path(tmp)/'flags.tar';writer=new();entry=entry_new()
            self.assertTrue(writer);self.assertTrue(entry)
            try:
                self.assertEqual(fmt(writer),0)
                self.assertEqual(opened(writer,str(archive).encode()),0)
                path(entry,b'payload');mode(entry,stat.S_IFREG|0o444);size(entry,0)
                uid(entry,2**33+17);gid(entry,2**33+29)
                mtime(entry,2**33+31,123456789)
                self.assertIsNone(flags(entry,b'schg'))
                self.assertEqual(header(writer,entry),0);self.assertEqual(close(writer),0)
            finally:
                entry_free(entry);free(writer)
            records=archive_headers.read(archive, library=LIBRARY)
            self.assertEqual(len(records),1)
            self.assertEqual((records[0]['uid'],records[0]['gid']),(2**33+17,2**33+29))
            self.assertEqual((records[0]['mtime'],records[0]['mtime_nsec']),(2**33+31,123456789))
            self.assertTrue(records[0]['mtime_is_set'])
            self.assertEqual(records[0]['size'],0)
            self.assertNotEqual(records[0]['fflags'],[0,0])
            archive_headers.check_flags(records[0],'schg',library=LIBRARY)
            with self.assertRaises(ValueError):
                archive_headers.check_flags(dict(records[0],fflags=[0,0]),'schg',library=LIBRARY)
            with self.assertRaises(ValueError):
                archive_headers.check_flags(records[0],'none',library=LIBRARY)

    def test_native_writer_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = Path(tmp) / 'payload'
            payload.write_bytes(b'flagged payload')
            base = dict(owner='root', group='wheel', mode='0444', tags=[])
            request = dict(epoch=0, users={'root': 0}, groups={'wheel': 0}, records=[
                dict(base, destination='/', type='dir', mode='0755'),
                dict(base, destination='/payload', type='file', source=str(payload), flags='schg')])
            for flag in ['schg', 'uchg', 'none', '']:
                request['records'][1]['flags'] = flag
                archive = Path(tmp) / 'native.tar'
                write_archive(request, archive)
                entry = next(r for r in archive_headers.read(archive, payload_digests=True, library=LIBRARY) if r['pathname'] == 'payload')
                self.assertEqual(entry['data_sha256'],hashlib.sha256(payload.read_bytes()).hexdigest())
                archive_headers.check_flags(entry, flag,library=LIBRARY)
                self.assertEqual((entry['mtime'],entry['mtime_nsec']),(0,0))
                self.assertTrue(entry['mtime_is_set'])
                self.assertEqual(entry['size'],len(payload.read_bytes()))
            request['records'][1]['flags'] = 'not-a-real-flag'
            with self.assertRaisesRegex(ValueError, 'unqualified filesystem flags'):
                write_archive(request, Path(tmp) / 'invalid.tar')
            request['records'][1]['flags'] = 'schg'
            request['records'].append(dict(base, destination='/alias', type='hardlink', link='/payload', flags='uchg'))
            with self.assertRaisesRegex(ValueError, 'hardlink inode metadata differs'):
                write_archive(request, Path(tmp) / 'mismatch.tar')

    def test_nonboolean_payload_mode_rejected(self):
        with self.assertRaisesRegex(ValueError,'payload_digests must be boolean'):
            archive_headers.read(Path('unused'),payload_digests=1)

    def test_unknown_flags_rejected(self):
        with self.assertRaises(ValueError):archive_headers.flag_bits('not-a-real-flag',library=LIBRARY)
        self.assertEqual(archive_headers.flag_bits('none',library=LIBRARY),[0,0])


if __name__=='__main__':unittest.main()
