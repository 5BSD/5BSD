# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import tempfile
import unittest
from installed_disk_evidence import disk_digest, require_disk


class DiskEvidenceTests(unittest.TestCase):
    def test_unchanged_and_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            disk = Path(directory) / 'disk'
            disk.write_bytes(b'first image')
            expected = disk_digest(disk)
            self.assertEqual(require_disk(disk, expected), expected)
            disk.write_bytes(b'other image')
            with self.assertRaisesRegex(ValueError, 'changed'):
                require_disk(disk, expected)

    def test_missing_and_malformed_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            disk = Path(directory) / 'disk'
            disk.write_bytes(b'image')
            for value in (None, '', '0'*63, 'g'*64, 123, 'A'*64):
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'valid SHA-256'):
                    require_disk(disk, value)

    def test_missing_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                require_disk(Path(directory) / 'missing', '0'*64)


if __name__ == '__main__':
    unittest.main()
