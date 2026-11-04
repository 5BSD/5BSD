# SPDX-License-Identifier: BSD-2-Clause
"""Content verification, corrupt-input rejection and bounded hash concurrency."""
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import sdk_digests


class DigestTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.expected = {}
        for number in range(19):
            name = 'file-' + str(number)
            data = bytes([number]) * (4096 + number)
            (self.root / name).write_bytes(data)
            self.expected[name] = hashlib.sha256(data).hexdigest()

    def verify(self, expected=None, jobs=4, **kwargs):
        return sdk_digests.verify(self.expected if expected is None else expected,
            jobs=jobs, prefix='changed: ', root=self.root, **kwargs)

    def test_all_files_and_bytes_in_serial_and_parallel(self):
        expected_size = sum((self.root / name).stat().st_size for name in self.expected)
        for jobs in [1, 4, 100]:
            with self.subTest(jobs=jobs):
                result = self.verify(jobs=jobs)
                self.assertEqual(result['files'], 19)
                self.assertEqual(result['logical_bytes'], expected_size)
                self.assertEqual(result['workers'], min(jobs, 19))
                self.assertGreaterEqual(result['elapsed_seconds'], 0)

    def test_absolute_origin_mapping(self):
        absolute = {str(self.root / name): value for name, value in self.expected.items()}
        self.assertEqual(sdk_digests.verify(absolute, jobs=4, prefix='origin: ')['files'], 19)

    def test_same_mtime_and_size_corruption_rejected(self):
        path = self.root / 'file-7'
        before = path.stat()
        data = bytearray(path.read_bytes()); data[2048] ^= 1; path.write_bytes(data)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(path.stat().st_size, before.st_size)
        self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)
        for jobs in [1, 4]:
            with self.subTest(jobs=jobs), self.assertRaisesRegex(ValueError, '^changed: file-7$'):
                self.verify(jobs=jobs)

    def test_each_verification_rereads_content(self):
        self.verify()
        (self.root / 'file-0').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, '^changed: file-0$'):
            self.verify()

    def test_missing_file_rejected(self):
        (self.root / 'file-3').unlink()
        for jobs in [1, 4]:
            with self.subTest(jobs=jobs), self.assertRaises(FileNotFoundError):
                self.verify(jobs=jobs)

    def test_unsafe_snapshot_names_rejected_before_reads(self):
        for name in ['../outside', '/absolute', 'directory/../../outside']:
            with self.subTest(name=name), patch.object(sdk_digests, '_hash_file') as read:
                with self.assertRaisesRegex(ValueError, '^changed: '):
                    self.verify({**self.expected, name: '0' * 64})
                read.assert_not_called()

    def test_empty_and_invalid_jobs(self):
        self.assertEqual(self.verify({})['files'], 0)
        self.assertEqual(self.verify({})['workers'], 0)
        for jobs in [0, -1, True, 1.5]:
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                self.verify(jobs=jobs)

    def test_parallel_readers_are_bounded_and_all_entries_read(self):
        original = sdk_digests._hash_file
        lock = threading.Lock(); barrier = threading.Barrier(4, timeout=10)
        active = maximum = started = 0
        seen = []
        def read(path):
            nonlocal active, maximum, started
            with lock:
                active += 1; maximum = max(maximum, active); started += 1
                first_batch = started <= 4; seen.append(path.name)
            try:
                if first_batch:
                    barrier.wait()
                return original(path)
            finally:
                with lock:
                    active -= 1
        with patch.object(sdk_digests, '_hash_file', read):
            self.verify(jobs=4)
        self.assertEqual(maximum, 4)
        self.assertEqual(active, 0)
        self.assertCountEqual(seen, self.expected)


if __name__ == '__main__':
    unittest.main()
