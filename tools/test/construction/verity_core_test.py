# SPDX-License-Identifier: BSD-2-Clause
"""Native C verifier tests using the independent Python tree builder."""
import ctypes as C
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

lib = C.CDLL(str(Path(sys.argv.pop(1)).resolve()))
path = Path(__file__).resolve().parents[2] / 'build/capimage/verity_tree.py'
spec = importlib.util.spec_from_file_location('tree', path)
tree = importlib.util.module_from_spec(spec); spec.loader.exec_module(tree)
Reader = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_int, C.c_uint64, C.c_void_p, C.c_size_t)
lib.g_verity_verify.argtypes = [C.c_uint64, C.c_uint32, C.c_void_p, C.c_size_t,
    C.c_void_p, C.c_uint64, Reader, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p]
lib.g_verity_verify.restype = C.c_int
lib.g_verity_read_range.argtypes = [C.c_uint64, C.c_uint32, C.c_void_p, C.c_size_t,
    C.c_void_p, C.c_uint64, C.c_size_t, Reader, C.c_void_p, C.c_void_p,
    C.c_void_p, C.c_void_p, C.c_void_p]
lib.g_verity_read_range.restype = C.c_int



class Layout(C.Structure):
    _fields_ = [('data_bytes', C.c_uint64), ('tree_bytes', C.c_uint64),
                ('offsets', C.c_uint64 * 16), ('block_size', C.c_uint32),
                ('levels', C.c_uint32)]


class Root(C.Structure):
    _fields_ = [('layout', Layout), ('root_hash', C.c_ubyte * 32),
                ('salt', C.c_ubyte * 256), ('salt_len', C.c_uint32),
                ('filesystem', C.c_uint32)]


class Cache(C.Structure):
    _fields_ = [('root', Root), ('tags', C.POINTER(C.c_uint64)),
                ('blocks', C.c_void_p), ('entries', C.c_size_t), ('initialized', C.c_uint)]

lib.g_verity_cache_init.argtypes = [C.POINTER(Cache), C.POINTER(Root),
    C.POINTER(C.c_uint64), C.c_void_p, C.c_size_t]
lib.g_verity_cache_init.restype = C.c_int
lib.g_verity_cached_read_range.argtypes = [C.POINTER(Cache), C.c_uint64,
    C.c_size_t, Reader, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p]
lib.g_verity_cached_read_range.restype = C.c_int

lib.g_verity_root_decode.argtypes = [C.c_void_p, C.c_size_t, C.POINTER(Root)]
lib.g_verity_root_decode.restype = C.c_int


class Descriptor(unittest.TestCase):
    def wire(self):
        return tree.encode_root_descriptor(129 * 4096, 4096, b'salt', bytes(range(32)))

    def test_cross_language_decode(self):
        value = Root()
        wire = self.wire()
        self.assertEqual(len(wire), 384)
        self.assertEqual(lib.g_verity_root_decode(wire, len(wire), C.byref(value)), 0)
        self.assertEqual(value.layout.data_bytes, 129 * 4096)
        self.assertEqual(value.layout.tree_bytes, 3 * 4096)
        self.assertEqual(value.layout.block_size, 4096)
        self.assertEqual(value.layout.levels, 2)
        self.assertEqual(list(value.layout.offsets)[:2], [4096, 0])
        self.assertEqual(bytes(value.root_hash), bytes(range(32)))
        self.assertEqual(value.salt_len, 4)
        self.assertEqual(bytes(value.salt)[:4], b'salt')
        self.assertEqual(value.filesystem, 1)

    def test_invalid_fields_and_lengths_leave_output_unchanged(self):
        valid = self.wire()
        variants = [valid[:-1], valid + b'\0']
        for offset in (0, 8, 12, 16, 20, 24, 28, 32, 40, 80, 88, 383):
            wire = bytearray(valid); wire[offset] ^= 0x80
            variants.append(bytes(wire))
        for wire in variants:
            value = Root()
            C.memset(C.byref(value), 0x51, C.sizeof(value))
            self.assertNotEqual(lib.g_verity_root_decode(wire, len(wire), C.byref(value)), 0)
            self.assertEqual(bytes(value), b'Q' * C.sizeof(value))

    def test_parsing_does_not_authenticate_digest(self):
        wire = bytearray(self.wire()); wire[48] ^= 1
        value = Root()
        self.assertEqual(lib.g_verity_root_decode(bytes(wire), len(wire), C.byref(value)), 0)
        self.assertEqual(value.root_hash[0], 1)


class Core(unittest.TestCase):
    def setUp(self):
        self.data = tempfile.TemporaryFile(); self.hashes = tempfile.TemporaryFile()
        self.addCleanup(self.data.close); self.addCleanup(self.hashes.close)
        self.size = 129 * 4096
        self.data.truncate(self.size)
        os.pwrite(self.data.fileno(), b'nonzero data', 128 * 4096)
        self.salt = b'fixed-test-salt'
        self.root = tree.build_tree(self.data.fileno(), self.hashes.fileno(),
                                   self.size, 4096, self.salt)
        self.failure = None
        self.requests = []

    def verify(self, index, root=None, size=None, block=4096):
        @Reader
        def reader(arg, hashes, offset, destination, length):
            self.requests.append((hashes, offset, length))
            if self.failure is not None:
                return self.failure
            data = os.pread((self.hashes if hashes else self.data).fileno(), length, offset)
            if len(data) != length:
                return errno.EIO
            C.memmove(destination, data, length)
            return 0
        data = C.create_string_buffer(65536)
        hashes = C.create_string_buffer(65536)
        output = C.create_string_buffer(b'Q' * 65536, 65536)
        result = lib.g_verity_verify(self.size if size is None else size, block,
            self.salt, len(self.salt), self.root if root is None else root,
            index, reader, None, data, hashes, output)
        return result, output.raw

    def read_range(self, offset, length, fail_at=None, before_read=None):
        @Reader
        def reader(arg, hashes, source_offset, destination, count):
            self.requests.append((hashes, source_offset, count))
            if before_read is not None:
                before_read(hashes, source_offset)
            if not hashes and source_offset == fail_at:
                return errno.ENXIO
            content = os.pread((self.hashes if hashes else self.data).fileno(),
                               count, source_offset)
            if len(content) != count:
                return errno.EIO
            C.memmove(destination, content, count)
            return 0
        data, hashes, verified = (C.create_string_buffer(4096) for _ in range(3))
        output = C.create_string_buffer(b'Q' * (length + 16), length + 16)
        result = lib.g_verity_read_range(self.size, 4096, self.salt,
            len(self.salt), self.root, offset, length, reader, None,
            data, hashes, verified, C.byref(output, 8))
        self.assertEqual(output.raw[:8], b'Q' * 8)
        self.assertEqual(output.raw[-8:], b'Q' * 8)
        return result, output.raw[8:-8]

    def cache(self, entries=8, root_hash=None):
        root = Root()
        wire = tree.encode_root_descriptor(self.size, 4096, self.salt,
            self.root if root_hash is None else root_hash)
        self.assertEqual(lib.g_verity_root_decode(wire, len(wire), C.byref(root)), 0)
        cache = Cache()
        tags = (C.c_uint64 * entries)()
        blocks = C.create_string_buffer(max(1, entries * 4096))
        self.assertEqual(lib.g_verity_cache_init(C.byref(cache), C.byref(root),
            tags, blocks, entries), 0)
        return cache, tags, blocks

    def cached_read(self, state, offset, length, before_read=None):
        @Reader
        def reader(arg, hashes, pos, destination, count):
            self.requests.append((hashes, pos, count))
            if before_read is not None:
                before_read(hashes, pos)
            if self.failure is not None:
                return self.failure
            content = os.pread((self.hashes if hashes else self.data).fileno(), count, pos)
            if len(content) != count:
                return errno.EIO
            C.memmove(destination, content, count)
            return 0
        data, hashes = (C.create_string_buffer(4096) for _ in range(2))
        output = C.create_string_buffer(b'Q' * (length + 16), length + 16)
        result = lib.g_verity_cached_read_range(C.byref(state[0]), offset, length,
            reader, None, data, hashes, C.byref(output, 8))
        self.assertEqual(output.raw[:8] + output.raw[-8:], b'Q' * 16)
        return result, output.raw[8:-8]

    def test_each_read_failure_clears_output_and_allows_authentic_retry(self):
        # Cross a leaf boundary after returning some verified bytes. An I/O
        # callback may overwrite part of its destination before reporting an
        # error: those bytes must not escape or poison the retained hash cache.
        offset, length = 127 * 4096 - 1, 4098
        expected = os.pread(self.data.fileno(), length, offset)

        def run(state, fail_call=None, error=errno.EIO):
            calls = []
            @Reader
            def reader(arg, hashes, pos, destination, count):
                calls.append((hashes, pos, count))
                if len(calls) == fail_call:
                    C.memset(destination, 0xa5, count // 2)
                    return error
                content = os.pread((self.hashes if hashes else self.data).fileno(),
                                   count, pos)
                if len(content) != count:
                    return errno.EIO
                C.memmove(destination, content, count)
                return 0
            scratch = [C.create_string_buffer(4096) for _ in range(3)]
            output = C.create_string_buffer(b'Q' * (length + 16), length + 16)
            if state is None:
                result = lib.g_verity_read_range(self.size, 4096, self.salt,
                    len(self.salt), self.root, offset, length, reader, None,
                    *scratch, C.byref(output, 8))
            else:
                result = lib.g_verity_cached_read_range(C.byref(state[0]),
                    offset, length, reader, None, *scratch[:2], C.byref(output, 8))
            self.assertEqual(output.raw[:8] + output.raw[-8:], b'Q' * 16)
            return result, output.raw[8:-8], calls

        for entries in (None, 0, 1, 8):
            for warm in (False, True):
                def fresh():
                    state = None if entries is None else self.cache(entries)
                    if warm:
                        self.assertEqual(run(state)[:2], (0, expected))
                    return state
                result, output, successful_calls = run(fresh())
                self.assertEqual((result, output), (0, expected))
                for fail_call in range(1, len(successful_calls) + 1):
                    for error in (errno.EIO, errno.ENXIO, errno.EINTR, errno.ECANCELED):
                        with self.subTest(entries=entries, warm=warm,
                                          fail_call=fail_call, error=error):
                            state = fresh()
                            result, output, calls = run(state, fail_call, error)
                            self.assertEqual((result, output), (error, bytes(length)))
                            self.assertEqual(calls, successful_calls[:fail_call])
                            # Retry with the SAME cache, including any entries
                            # authenticated before the failing callback.
                            self.assertEqual(run(state)[:2], (0, expected))

    def test_replayed_ranges_authenticate_each_consumed_read(self):
        # Model a loader rereading headers/segments, including data and tree
        # boundaries. Retained hash blocks must never authorize new bad bytes.
        for entries in (None, 0, 1, 8):
            state = None if entries is None else self.cache(entries)
            read = self.read_range if state is None else (
                lambda offset, length: self.cached_read(state, offset, length))
            for offset in (0, 4090, 127 * 4096 - 3):
                with self.subTest(entries=entries, offset=offset):
                    length = 17
                    original = os.pread(self.data.fileno(), length, offset)
                    self.assertEqual(read(offset, length), (0, original))
                    # Consume a later region before the backward replay.
                    self.assertEqual(read(128 * 4096, 32),
                        (0, os.pread(self.data.fileno(), 32, 128 * 4096)))
                    changed = bytes([original[0] ^ 0xff]) + original[1:]
                    try:
                        os.pwrite(self.data.fileno(), changed, offset)
                        self.assertEqual(read(offset, length),
                            (errno.EAUTH, bytes(length)))
                    finally:
                        os.pwrite(self.data.fileno(), original, offset)
                    # Restoring authentic bytes permits a new read; the prior
                    # failed read returned no consumable unauthenticated bytes.
                    self.assertEqual(read(offset, length), (0, original))

    def test_cache_bounds_eviction_and_reference_equivalence(self):
        for entries in (0, 1, 2, 8):
            state = self.cache(entries)
            for offset, length in ((0, 8192), (4095, 3), (127 * 4096, 8192),
                                   (0, self.size), (self.size, 0)):
                self.assertEqual(self.cached_read(state, offset, length),
                    (0, os.pread(self.data.fileno(), length, offset)))
            self.assertEqual(self.cached_read(state, self.size, 1), (errno.EINVAL, b'Q'))
        state = self.cache()
        self.requests = []
        self.assertEqual(self.cached_read(state, 0, 4096), (0, bytes(4096)))
        self.assertEqual(sum(bool(h) for h, _, _ in self.requests), 2)
        self.requests = []
        self.assertEqual(self.cached_read(state, 4096, 4096), (0, bytes(4096)))
        self.assertEqual(self.requests, [(0, 4096, 4096)])

    def test_small_cache_does_not_repeat_path_within_leaf(self):
        for entries in (0, 1, 2):
            state = self.cache(entries)
            self.requests = []
            self.assertEqual(self.cached_read(state, 0, 32 * 4096),
                             (0, bytes(32 * 4096)))
            self.assertEqual(sum(bool(h) for h, _, _ in self.requests), 2)
            self.assertEqual(sum(not h for h, _, _ in self.requests), 32)

    def test_cache_data_tamper_and_io_failure_clear_prefix(self):
        state = self.cache()
        self.assertEqual(self.cached_read(state, 0, 4096)[0], 0)
        def mutate(hashes, offset):
            if not hashes and offset == 4096:
                changed = b'X' * 4096
                os.pwrite(self.data.fileno(), changed, offset)
                os.pwrite(self.hashes.fileno(), hashlib.sha256(self.salt + changed).digest(), 4096 + 32)
        self.assertEqual(self.cached_read(state, 0, 8192, mutate), (errno.EAUTH, bytes(8192)))
        self.failure = errno.ENXIO
        self.assertEqual(self.cached_read(state, 0, 4096), (errno.ENXIO, bytes(4096)))

    def test_cache_retains_bytes_but_rebind_clears_them(self):
        state = self.cache()
        self.assertEqual(self.cached_read(state, 0, 4096)[0], 0)
        os.pwrite(self.hashes.fileno(), b'X' * 4096, 0)
        self.assertEqual(self.cached_read(state, 0, 4096), (0, bytes(4096)))
        root = Root.from_buffer_copy(state[0].root)
        self.assertEqual(lib.g_verity_cache_init(C.byref(state[0]), C.byref(root),
            state[1], state[2], len(state[1])), 0)
        self.assertEqual(self.cached_read(state, 0, 4096), (errno.EAUTH, bytes(4096)))

    def test_cache_successful_generation_and_salt_rebind(self):
        state = self.cache()
        self.assertEqual(self.cached_read(state, 0, 4096)[0], 0)
        os.pwrite(self.data.fileno(), b'new generation', 0)
        self.assertEqual(self.cached_read(state, 0, 4096)[0], errno.EAUTH)
        self.salt = b'different salt'
        self.hashes.truncate(0)
        self.root = tree.build_tree(self.data.fileno(), self.hashes.fileno(),
            self.size, 4096, self.salt)
        root = Root()
        wire = tree.encode_root_descriptor(self.size, 4096, self.salt, self.root)
        self.assertEqual(lib.g_verity_root_decode(wire, len(wire), C.byref(root)), 0)
        self.assertEqual(lib.g_verity_cache_init(C.byref(state[0]), C.byref(root),
            state[1], state[2], len(state[1])), 0)
        self.assertEqual(self.cached_read(state, 0, 4096),
            (0, os.pread(self.data.fileno(), 4096, 0)))

    def test_cache_rebind_new_root_and_failed_initialization(self):
        state = self.cache()
        self.assertEqual(self.cached_read(state, 0, 4096)[0], 0)
        root = Root.from_buffer_copy(state[0].root)
        root.root_hash[0] ^= 1
        self.assertEqual(lib.g_verity_cache_init(C.byref(state[0]), C.byref(root),
            state[1], state[2], len(state[1])), 0)
        self.assertEqual(self.cached_read(state, 0, 4096), (errno.EAUTH, bytes(4096)))
        before = bytes(state[0])
        root.layout.tree_bytes += 4096
        self.assertEqual(lib.g_verity_cache_init(C.byref(state[0]), C.byref(root),
            state[1], state[2], len(state[1])), errno.EINVAL)
        self.assertEqual(bytes(state[0]), before)

    def test_range_partial_and_tree_boundaries(self):
        for offset, length in ((0, 1), (4095, 2), (127 * 4096 - 3, 4100),
                               (128 * 4096, 11), (self.size - 1, 1),
                               (0, self.size)):
            self.requests = []
            self.assertEqual(self.read_range(offset, length),
                             (0, os.pread(self.data.fileno(), length, offset)))
            first = offset // 4096
            last = (offset + length - 1) // 4096
            self.assertEqual([pos for is_hash, pos, _ in self.requests if not is_hash],
                             [index * 4096 for index in range(first, last + 1)])
            self.assertTrue(all(n == 4096 for _, _, n in self.requests))

    def test_range_reuses_leaf_within_request_only(self):
        self.assertEqual(self.read_range(0, 32 * 4096), (0, bytes(32 * 4096)))
        self.assertEqual(sum(bool(h) for h, _, _ in self.requests), 2)
        self.requests = []
        self.assertEqual(self.read_range(0, self.size)[0], 0)
        self.assertEqual(sum(bool(h) for h, _, _ in self.requests), 4)
        # A later request must authenticate the tree afresh.
        os.pwrite(self.hashes.fileno(), b'changed', 4096)
        self.assertEqual(self.read_range(0, 4096), (errno.EAUTH, bytes(4096)))

    def test_cached_leaf_rejects_changed_data_and_matching_backing_hash(self):
        def mutate(hashes, offset):
            if not hashes and offset == 4096:
                altered = b'X' * 4096
                os.pwrite(self.data.fileno(), altered, offset)
                os.pwrite(self.hashes.fileno(),
                    hashlib.sha256(self.salt + altered).digest(), 4096 + 32)
        self.assertEqual(self.read_range(0, 8192, before_read=mutate),
                         (errno.EAUTH, bytes(8192)))

    def test_retained_leaf_bytes_survive_backing_tree_mutation(self):
        def mutate(hashes, offset):
            if not hashes and offset == 4096:
                os.pwrite(self.hashes.fileno(), b'X' * 4096, 4096)
        # Authenticated retained bytes remain valid for the original root.
        self.assertEqual(self.read_range(0, 8192, before_read=mutate),
                         (0, bytes(8192)))
        self.assertEqual(self.read_range(0, 8192), (errno.EAUTH, bytes(8192)))

    def test_range_failure_clears_previously_verified_prefix(self):
        os.pwrite(self.data.fileno(), b'corrupt', 4096)
        self.assertEqual(self.read_range(4095, 2), (errno.EAUTH, bytes(2)))
        self.assertEqual(self.read_range(4095, 2, fail_at=4096),
                         (errno.ENXIO, bytes(2)))

    def test_range_verifies_bytes_outside_requested_slice(self):
        self.assertEqual(self.read_range(0, 1), (0, bytes(1)))
        os.pwrite(self.data.fileno(), b'corrupt', 4095)
        self.assertEqual(self.read_range(0, 1), (errno.EAUTH, bytes(1)))

    def test_range_bounds_and_empty_reads(self):
        for offset, length in ((self.size, 1), (self.size - 1, 2),
                               ((1 << 64) - 1, 2), (self.size + 1, 0)):
            self.assertEqual(self.read_range(offset, length),
                             (errno.EINVAL, b'Q' * length))
        for offset in (0, self.size):
            self.assertEqual(self.read_range(offset, 0), (0, b''))
        self.assertEqual(self.requests, [])

    def test_combined_builder_bytes_through_c_verifier(self):
        expected = hashlib.sha256(os.pread(self.data.fileno(), self.size, 0)).digest()
        with tempfile.TemporaryFile() as image:
            root = tree.build_image(self.data.fileno(), image.fileno(), self.size,
                                    4096, self.salt, expected)
            @Reader
            def reader(arg, is_hash, offset, destination, length):
                physical = offset + (self.size if is_hash else 0)
                content = os.pread(image.fileno(), length, physical)
                if len(content) != length:
                    return errno.EIO
                C.memmove(destination, content, length)
                return 0
            data, hashes, output = (C.create_string_buffer(4096) for _ in range(3))
            def verify(index):
                return lib.g_verity_verify(self.size, 4096, self.salt,
                    len(self.salt), root, index, reader, None, data, hashes, output)
            for index in range(129):
                self.assertEqual(verify(index), 0)
                self.assertEqual(output.raw, os.pread(self.data.fileno(), 4096, index * 4096))
            os.pwrite(image.fileno(), b'changed', 128 * 4096)
            self.assertEqual(verify(128), errno.EAUTH)
            os.pwrite(image.fileno(), b'changed', self.size)
            self.assertEqual(verify(0), errno.EAUTH)

    def test_valid_nonzero_and_level_boundaries(self):
        for index in (0, 127, 128):
            result, output = self.verify(index)
            self.assertEqual(result, 0)
            self.assertEqual(output[:4096], os.pread(self.data.fileno(), 4096, index * 4096))
            self.assertEqual(output[4096:], b'Q' * (65536 - 4096))
        self.assertTrue(all(length == 4096 for _, _, length in self.requests))

    def test_online_mutation_never_changes_output(self):
        self.assertEqual(self.verify(128)[0], 0)
        os.pwrite(self.data.fileno(), b'changed', 128 * 4096)
        result, output = self.verify(128)
        self.assertEqual(result, errno.EAUTH)
        self.assertEqual(output, b'Q' * 65536)

    def test_hash_and_root_corruption(self):
        result, output = self.verify(0, root=bytes(32))
        self.assertEqual(result, errno.EAUTH)
        self.assertEqual(output, b'Q' * 65536)
        os.pwrite(self.hashes.fileno(), b'x', 4095)
        result, output = self.verify(0)
        self.assertEqual(result, errno.EAUTH)
        self.assertEqual(output, b'Q' * 65536)

    def test_read_errors_propagate_without_output(self):
        self.failure = errno.ENXIO
        self.assertEqual(self.verify(0), (errno.ENXIO, b'Q' * 65536))
        self.failure = None
        self.hashes.truncate(1)
        self.assertEqual(self.verify(0), (errno.EIO, b'Q' * 65536))

    def test_invalid_geometry_rejected_before_io(self):
        for kwargs in ({'size': 1 << 63}, {'size': 4096}, {'block': 513},
                       {'block': 0}, {'block': 131072}):
            self.assertEqual(self.verify(0, **kwargs), (errno.EINVAL, b'Q' * 65536))
        self.assertEqual(self.verify(129), (errno.EINVAL, b'Q' * 65536))
        self.assertEqual(self.requests, [])


if __name__ == '__main__': unittest.main()
