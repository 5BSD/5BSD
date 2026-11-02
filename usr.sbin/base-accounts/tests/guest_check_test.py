#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check guest metadata/integrity boundaries and actual owned-process cleanup."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import time
import unittest

path = Path(__file__).with_name('guest_check.py')
spec = importlib.util.spec_from_file_location('guest', path)
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)
HEADER = 'Content-Type: application/X-atf-tp; version="1"\n\n'

class GuestBoundaries(unittest.TestCase):
    def test_full_listing_and_defaults(self):
        value = guest.listing(HEADER + 'ident: one\n\nident: two\ntimeout: 47\nhas.cleanup: true\n')
        self.assertEqual(list(value), ['one', 'two'])
        self.assertNotIn('timeout', value['one'])
        self.assertEqual(value['two']['timeout'], '47')
        self.assertEqual(value['two']['has.cleanup'], 'true')

    def test_duplicate_listing_is_error(self):
        with self.assertRaises(ValueError):
            guest.listing(HEADER + 'ident: one\n\nident: one\n')

    def test_invalid_metadata_is_error(self):
        for text in ['', 'ident: ../escape', 'ident: one\ntimeout: zero',
                     'ident: one\ntimeout: 0', 'ident: one\nhas.cleanup: maybe',
                     'ident: one\nrequire.user: root']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                guest.listing(HEADER + text)

    def test_manifest_changes_and_escapes_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            data = root / 'payload'
            data.write_bytes(b'original')
            expected = hashlib.sha256(b'original').hexdigest()
            guest.verify(root, {'files': {'payload': expected}})
            data.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                guest.verify(root, {'files': {'payload': expected}})
            with self.assertRaises(ValueError):
                guest.verify(root, {'files': {'../escape': expected}})
            link = root / 'escape'
            link.symlink_to('/bin/sh')
            with self.assertRaises(ValueError):
                guest.verify(root, {'files': {'escape': expected}})

    def test_actual_failed_command_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = guest.execute([sys.executable, '-c', 'import sys; print("kept"); sys.exit(7)'],
                                   None, 10, [], Path(temporary) / 'failure')
            self.assertEqual(result['exit_status'], 7)
            self.assertEqual(result['stdout'], 'kept\n')
            self.assertFalse(result['timed_out'])

    def test_actual_timeout_reaps_owned_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = guest.execute([sys.executable, '-c', 'import time; time.sleep(30)'],
                                   None, .1, [], Path(temporary) / 'timeout')
            self.assertTrue(result['timed_out'])
            self.assertLess(result['exit_status'], 0)

    def test_normal_exit_also_stops_descendants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / 'leaked-child'
            child = 'import time; from pathlib import Path; time.sleep(1); Path(' + repr(str(marker)) + ').touch()'
            parent = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c",' + repr(child) + '])'
            result = guest.execute([sys.executable, '-c', parent], None, 10, [], root / 'normal')
            self.assertEqual(result['exit_status'], 0)
            time.sleep(1.1)
            self.assertFalse(marker.exists(), 'normal phase leaked its descendant')

if __name__ == '__main__':
    unittest.main()
