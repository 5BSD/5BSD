#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Native checks for preserving source disks while preparing writable copies."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from disk_copy import check_source, copy_source


class DiskCopyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.data = bytes(range(256)) * 8193
        self.source.write_bytes(self.data)
        self.sha = hashlib.sha256(self.data).hexdigest()
        self.output = self.root / 'output'

    def copy(self, **options):
        return copy_source(options.get('source', self.source),
            options.get('sha', self.sha), options.get('size', len(self.data)), self.output)

    def test_private_independent_copy(self):
        self.copy()
        self.assertEqual(self.output.read_bytes(), self.data)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertNotEqual(self.output.stat().st_ino, self.source.stat().st_ino)
        self.output.write_bytes(b'guest writes')
        self.assertEqual(self.source.read_bytes(), self.data)

    def test_wrong_hash_before_output(self):
        with self.assertRaises(ValueError): self.copy(sha='0' * 64)
        self.assertFalse(self.output.exists())

    def test_wrong_size_before_output(self):
        with self.assertRaises(ValueError): self.copy(size=len(self.data) - 1)
        self.assertFalse(self.output.exists())

    def test_symlink_source_refused(self):
        link = self.root / 'link'; link.symlink_to(self.source)
        with self.assertRaises(OSError): self.copy(source=link)
        self.assertFalse(self.output.exists())

    def test_existing_destination_preserved(self):
        self.output.write_bytes(b'existing')
        with self.assertRaises(FileExistsError): self.copy()
        self.assertEqual(self.output.read_bytes(), b'existing')
        self.output.unlink(); self.output.symlink_to(self.source)
        with self.assertRaises(FileExistsError): self.copy()
        self.assertEqual(self.source.read_bytes(), self.data)

    def test_source_changes_detected(self):
        self.copy()
        self.source.write_bytes(b'x' * len(self.data))
        with self.assertRaises(ValueError): check_source(self.source, self.sha, len(self.data))

    def test_fifo_refused_without_blocking(self):
        fifo = self.root / 'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError): self.copy(source=fifo)
        self.assertFalse(self.output.exists())


if __name__ == '__main__': unittest.main()
