# SPDX-License-Identifier: BSD-2-Clause
"""Host component tests only; no kernel, VM or authenticated boot claim."""
import importlib.util
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

path = Path(__file__).resolve().parents[2] / 'build/capimage/verity_tree.py'
spec = importlib.util.spec_from_file_location('verity_tree', path)
verity = importlib.util.module_from_spec(spec); spec.loader.exec_module(verity)


class Tree(unittest.TestCase):
    def setUp(self):
        self.data = tempfile.TemporaryFile()
        self.tree = tempfile.TemporaryFile()
        self.addCleanup(self.data.close); self.addCleanup(self.tree.close)

    def build(self, size=129 * 4096, block=4096, salt=b'test-salt'):
        self.data.truncate(size)
        root = verity.build_tree(self.data.fileno(), self.tree.fileno(), size, block, salt)
        return lambda index: verity.read_verified_block(self.data.fileno(), self.tree.fileno(),
            size, block, salt, root, index)

    def test_combined_image_matches_separate_layout(self):
        size = 129 * 4096
        content = bytes(i % 251 for i in range(size))
        self.data.write(content); self.data.flush()
        root = verity.build_tree(self.data.fileno(), self.tree.fileno(),
                                 size, 4096, b'salt')
        with tempfile.TemporaryFile() as image:
            combined_root = verity.build_image(self.data.fileno(), image.fileno(),
                size, 4096, b'salt', hashlib.sha256(content).digest())
            self.assertEqual(combined_root, root)
            self.assertEqual(os.fstat(image.fileno()).st_size, size + 3 * 4096)
            self.assertEqual(os.pread(image.fileno(), size, 0), content)
            self.assertEqual(os.pread(image.fileno(), 3 * 4096, size),
                             os.pread(self.tree.fileno(), 3 * 4096, 0))

    def test_combined_rejects_wrong_digest_alias_and_existing_output(self):
        self.data.truncate(8192)
        expected = hashlib.sha256(bytes(8192)).digest()
        with self.assertRaises(ValueError):
            verity.build_image(self.data.fileno(), self.data.fileno(),
                               8192, 4096, b'', expected)
        self.tree.write(b'keep'); self.tree.flush()
        with self.assertRaises(ValueError):
            verity.build_image(self.data.fileno(), self.tree.fileno(),
                               8192, 4096, b'', expected)
        self.assertEqual(os.pread(self.tree.fileno(), 4, 0), b'keep')
        self.tree.truncate(0)
        with self.assertRaisesRegex(ValueError, 'expected filesystem digest'):
            verity.build_image(self.data.fileno(), self.tree.fileno(),
                               8192, 4096, b'', bytes(32))
        # Failure output is explicitly partial, not a signed/published artifact.
        self.assertEqual(os.fstat(self.tree.fileno()).st_size, 8192)

    def test_combined_copy_and_tree_io_remain_block_bounded(self):
        self.data.truncate(129 * 4096)
        expected = hashlib.sha256(bytes(129 * 4096)).digest()
        original_read, original_write = os.pread, os.pwrite
        def bounded_read(fd, size, offset):
            self.assertLessEqual(size, 4096)
            return original_read(fd, size, offset)
        def bounded_write(fd, data, offset):
            self.assertLessEqual(len(data), 4096)
            return original_write(fd, data, offset)
        with patch.object(verity.os, 'pread', bounded_read), \
             patch.object(verity.os, 'pwrite', bounded_write):
            verity.build_image(self.data.fileno(), self.tree.fileno(),
                               129 * 4096, 4096, b'', expected)

    def test_combined_extent_overflow_precedes_io(self):
        with patch.object(verity.os, 'fstat', side_effect=AssertionError('unexpected I/O')):
            with self.assertRaisesRegex(ValueError, 'combined extent'):
                verity.build_image(0, 1, verity.MAX_OFFSET // 4096 * 4096,
                                   4096, b'', bytes(32))

    def test_upstream_root_vectors(self):
        # Numeric test vectors from cryptsetup v2.7.5 tests/verity-compat-test:
        # https://gitlab.com/cryptsetup/cryptsetup/-/blob/v2.7.5/tests/verity-compat-test
        # Input: 8192 KiB of zero bytes; equal data/hash block sizes, format 1.
        salt = bytes.fromhex('e48da609055204e89ae53b655ca2216dd983cf3cb829f34f63a297d106d53e2d')
        vectors = {512: '9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174',
            1024: '54d92778750495d1f80832b486ebd007617d746271511bbf0e295e143da2b3df',
            4096: 'e522df0f97da4febb882ac40f30b37dc0b444bf6df418929463fa25280f09d5c'}
        for block, expected in vectors.items():
            with self.subTest(block=block):
                self.tree.truncate(0); self.data.truncate(8 * 1024 * 1024)
                root = verity.build_tree(self.data.fileno(), self.tree.fileno(),
                                        8 * 1024 * 1024, block, salt)
                self.assertEqual(root.hex(), expected)

    def test_boundary_reads_and_online_data_tampering(self):
        read = self.build()
        for index in (0, 127, 128):
            self.assertEqual(read(index), bytes(4096))
        os.pwrite(self.data.fileno(), b'changed', 128 * 4096)
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            read(128)
        self.assertEqual(read(0), bytes(4096))

    def test_hash_padding_tampering_and_truncation(self):
        read = self.build()
        read(128)
        os.pwrite(self.tree.fileno(), b'x', 4095)  # unused but authenticated root padding
        with self.assertRaises(ValueError): read(128)
        self.tree.truncate(1)
        with self.assertRaises(ValueError): read(0)

    def test_read_bounds_and_wrong_root(self):
        read = self.build()
        for index in (-1, 129, True):
            with self.assertRaises(ValueError): read(index)
        with self.assertRaisesRegex(ValueError, 'root digest'):
            verity.read_verified_block(self.data.fileno(), self.tree.fileno(),
                129 * 4096, 4096, b'test-salt', bytes(32), 0)
        self.data.truncate(1)
        with self.assertRaises(ValueError): read(0)

    def test_invalid_geometry(self):
        for size, block in ((0,4096), (4096,4096), (8193,4096),
                            (8192,True), (8192,513), (1 << 63,4096)):
            with self.assertRaises(ValueError): verity.geometry(size, block)

    def test_input_output_alias_and_nonempty_destination(self):
        self.data.truncate(8192)
        with self.assertRaises(ValueError):
            verity.build_tree(self.data.fileno(), self.data.fileno(), 8192, 4096, b'')
        self.tree.write(b'keep'); self.tree.flush()
        with self.assertRaises(ValueError):
            verity.build_tree(self.data.fileno(), self.tree.fileno(), 8192, 4096, b'')
        self.assertEqual(os.pread(self.tree.fileno(), 4, 0), b'keep')

    def test_io_requests_remain_block_bounded(self):
        original = os.pread
        def bounded(fd, size, offset):
            self.assertLessEqual(size, 4096)
            return original(fd, size, offset)
        with patch.object(verity.os, 'pread', side_effect=bounded):
            read = self.build(16385 * 4096)
            self.assertEqual(read(16384), bytes(4096))


if __name__ == '__main__': unittest.main()
