#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual archive flag serialization and rejection of dropped flags."""
import ctypes as C
from pathlib import Path
import stat
import tempfile
import unittest
import archive_headers
from install_archive import write_archive


class ArchiveFlags(unittest.TestCase):
    def test_real_pax_header_flags(self):
        lib=C.CDLL(str(archive_headers.LIBRARY))
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
        flags=bind('archive_entry_copy_fflags_text',[C.c_void_p,C.c_char_p],C.c_char_p)
        with tempfile.TemporaryDirectory() as tmp:
            archive=Path(tmp)/'flags.tar';writer=new();entry=entry_new()
            self.assertTrue(writer);self.assertTrue(entry)
            try:
                self.assertEqual(fmt(writer),0)
                self.assertEqual(opened(writer,str(archive).encode()),0)
                path(entry,b'payload');mode(entry,stat.S_IFREG|0o444);size(entry,0)
                self.assertIsNone(flags(entry,b'schg'))
                self.assertEqual(header(writer,entry),0);self.assertEqual(close(writer),0)
            finally:
                entry_free(entry);free(writer)
            records=archive_headers.read(archive)
            self.assertEqual(len(records),1)
            self.assertNotEqual(records[0]['fflags'],[0,0])
            archive_headers.check_flags(records[0],'schg')
            with self.assertRaises(ValueError):
                archive_headers.check_flags(dict(records[0],fflags=[0,0]),'schg')
            with self.assertRaises(ValueError):
                archive_headers.check_flags(records[0],'none')

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
                entry = next(r for r in archive_headers.read(archive) if r['pathname'] == 'payload')
                archive_headers.check_flags(entry, flag)
            request['records'][1]['flags'] = 'not-a-real-flag'
            with self.assertRaisesRegex(ValueError, 'unqualified filesystem flags'):
                write_archive(request, Path(tmp) / 'invalid.tar')
            request['records'][1]['flags'] = 'schg'
            request['records'].append(dict(base, destination='/alias', type='hardlink', link='/payload', flags='uchg'))
            with self.assertRaisesRegex(ValueError, 'hardlink inode metadata differs'):
                write_archive(request, Path(tmp) / 'mismatch.tar')

    def test_unknown_flags_rejected(self):
        with self.assertRaises(ValueError):archive_headers.flag_bits('not-a-real-flag')
        self.assertEqual(archive_headers.flag_bits('none'),[0,0])


if __name__=='__main__':unittest.main()
