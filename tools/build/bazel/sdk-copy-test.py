#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""SDK copies retain bytes/metadata and isolate writes across COW/fallback paths."""
import errno
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock
import sdk_copy as sdk


class CopyTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / 'source'
        self.destination = self.root / 'copy'
        self.payload = bytes(range(256)) * 8192 + b'partial block tail'
        self.source.write_bytes(self.payload)
        self.source.chmod(0o751)
        os.utime(self.source, ns=(1500000000000000000, 1500000000123456789))

    def assert_copy(self):
        self.assertEqual(self.destination.read_bytes(), self.payload)
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o751)
        self.assertEqual(self.destination.stat().st_mtime_ns, self.source.stat().st_mtime_ns)
        self.assertFalse(self.source.samefile(self.destination))

    def test_copy_and_bidirectional_write_isolation(self):
        sdk.copy2(self.source, self.destination)
        self.assert_copy()
        with self.destination.open('r+b') as stream:
            stream.write(b'COPY')
        self.assertEqual(self.source.read_bytes(), self.payload)
        with self.source.open('r+b') as stream:
            stream.seek(64)
            stream.write(b'SOURCE')
        self.assertEqual(self.destination.read_bytes()[64:70], self.payload[64:70])

    def test_tree_copy_matches_existing_symlink_and_metadata_policy(self):
        tree = self.root / 'tree'
        (tree / 'real').mkdir(parents=True)
        (tree / 'real' / 'header').write_bytes(b'header bytes')
        (tree / 'file-link').symlink_to('real/header')
        (tree / 'directory-link').symlink_to('real', target_is_directory=True)
        def inventory(root):
            result = {}
            for path in root.rglob('*'):
                info = path.lstat()
                payload = os.readlink(path) if path.is_symlink() else path.read_bytes() if path.is_file() else None
                result[str(path.relative_to(root))] = (info.st_mode, info.st_mtime_ns, payload)
            return result
        for symlinks in [False, True]:
            with self.subTest(symlinks=symlinks):
                ordinary = self.root / ('ordinary-' + str(symlinks))
                candidate = self.root / ('candidate-' + str(symlinks))
                shutil.copytree(tree, ordinary, symlinks=symlinks)
                shutil.copytree(tree, candidate, symlinks=symlinks, copy_function=sdk.copy2)
                self.assertEqual(inventory(candidate), inventory(ordinary))

    def test_no_offload_api(self):
        with mock.patch.object(sdk.os, 'copy_file_range', None, create=True):
            sdk.copy2(self.source, self.destination)
        self.assert_copy()

    def test_unsupported_after_partial_transfer_restarts_copy(self):
        def transfer(source_fd, destination_fd, count):
            if os.lseek(source_fd, 0, os.SEEK_CUR) == 0:
                return os.write(destination_fd, os.read(source_fd, 17))
            raise OSError(errno.EXDEV, 'cross-device offload unsupported')
        with mock.patch.object(sdk.os, 'copy_file_range', transfer, create=True):
            sdk.copy2(self.source, self.destination)
        self.assert_copy()

    def test_zero_progress_restarts_copy(self):
        with mock.patch.object(sdk.os, 'copy_file_range', return_value=0, create=True):
            sdk.copy2(self.source, self.destination)
        self.assert_copy()

    def test_storage_failure_is_not_hidden(self):
        with mock.patch.object(sdk.os, 'copy_file_range', side_effect=OSError(errno.ENOSPC, 'full'), create=True):
            with self.assertRaises(OSError) as raised:
                sdk.copy2(self.source, self.destination)
        self.assertEqual(raised.exception.errno, errno.ENOSPC)
        self.assertEqual(self.source.read_bytes(), self.payload)

    def test_same_file_is_rejected_before_truncation(self):
        self.destination.hardlink_to(self.source)
        with self.assertRaises(shutil.SameFileError):
            sdk.copy2(self.source, self.destination)
        self.assertEqual(self.source.read_bytes(), self.payload)


if __name__ == '__main__':
    unittest.main()
