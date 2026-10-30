# SPDX-License-Identifier: BSD-2-Clause
"""Bounded dm-verity v1/SHA-256 tree primitives, without a superblock.

Trusted-builder component only. The caller must authenticate geometry, salt and
root digest before using read_verified_block as an integrity boundary. This is
not a kernel provider, signing tool or installed-system qualification.
Layout reference: docs.kernel.org/admin-guide/device-mapper/verity.html
"""
import hashlib
import hmac
import os
import stat
import struct

MAX_OFFSET = (1 << 63) - 1


def geometry(data_bytes, block_size):
    if (type(block_size) is not int or not 512 <= block_size <= 65536 or
            block_size & (block_size - 1) or type(data_bytes) is not int or
            not 2 * block_size <= data_bytes <= MAX_OFFSET or
            data_bytes % block_size):
        raise ValueError('invalid verity geometry (requires at least two complete blocks)')
    fanout = block_size // 32
    counts = []
    count = data_bytes // block_size
    while count > 1:
        count = (count + fanout - 1) // fanout
        counts.append(count)
    # Count levels leaf-first; disk storage is root-first.
    offsets = [0] * len(counts)
    end = 0
    for level in reversed(range(len(counts))):
        offsets[level] = end
        end += counts[level] * block_size
        if end > MAX_OFFSET:
            raise ValueError('hash tree exceeds supported offsets')
    return tuple(counts), tuple(offsets), end


def checked_salt(salt):
    if type(salt) is not bytes or len(salt) > 256:
        raise ValueError('invalid verity salt')
    return salt


def read_exact(fd, size, offset):
    result = os.pread(fd, size, offset)
    if len(result) != size:
        raise ValueError('truncated verity input')
    return result


def write_exact(fd, data, offset):
    view = memoryview(data)
    while view:
        written = os.pwrite(fd, view, offset)
        if written <= 0:
            raise OSError('short verity tree write')
        view = view[written:]
        offset += written


def build_tree(data_fd, tree_fd, data_bytes, block_size, salt):
    """Write a tree to an empty distinct regular file; memory O(block_size).

    Inputs must remain quiescent. Failure leaves partial output for the caller
    to discard; no successful return authenticates the original data or tree.
    """
    counts, offsets, tree_bytes = geometry(data_bytes, block_size)
    salt = checked_salt(salt)
    source, target = os.fstat(data_fd), os.fstat(tree_fd)
    if (not stat.S_ISREG(source.st_mode) or not stat.S_ISREG(target.st_mode) or
            (source.st_dev, source.st_ino) == (target.st_dev, target.st_ino) or
            source.st_size != data_bytes or target.st_size != 0):
        raise ValueError('requires exact regular data file and empty distinct tree')
    return _write_tree(data_fd, tree_fd, data_bytes, block_size, salt, 0)


def _write_tree(data_fd, tree_fd, data_bytes, block_size, salt, tree_offset):
    """Internal writer; callers validate file ownership, extents and salt first."""
    counts, offsets, tree_bytes = geometry(data_bytes, block_size)
    source_fd, source_offset = data_fd, 0
    source_blocks = data_bytes // block_size
    fanout = block_size // 32
    for level, blocks in enumerate(counts):
        for block in range(blocks):
            hashes = bytearray(block_size)
            first = block * fanout
            for slot in range(min(fanout, source_blocks - first)):
                data = read_exact(source_fd, block_size,
                                  source_offset + (first + slot) * block_size)
                hashes[slot * 32:(slot + 1) * 32] = hashlib.sha256(salt + data).digest()
            write_exact(tree_fd, hashes, tree_offset + offsets[level] + block * block_size)
        source_fd, source_offset, source_blocks = tree_fd, tree_offset + offsets[level], blocks
    if os.fstat(tree_fd).st_size != tree_offset + tree_bytes:
        raise ValueError('unexpected completed tree size')
    return hashlib.sha256(salt + read_exact(tree_fd, block_size, tree_offset)).digest()


def read_verified_block(data_fd, tree_fd, data_bytes, block_size, salt, root, index):
    """Return only the exact data buffer whose entire path verified.

    No previously-verified-bit cache: every call reads and verifies again. Kernel
    integration must preserve these byte-identity semantics, including I/O errors.
    """
    counts, offsets, _ = geometry(data_bytes, block_size)
    salt = checked_salt(salt)
    if (type(root) is not bytes or len(root) != 32 or type(index) is not int or
            not 0 <= index < data_bytes // block_size):
        raise ValueError('invalid root digest or data block index')
    data = read_exact(data_fd, block_size, index * block_size)
    digest = hashlib.sha256(salt + data).digest()
    child = index
    for offset in offsets:
        block, slot = divmod(child, block_size // 32)
        hashes = read_exact(tree_fd, block_size, offset + block * block_size)
        if not hmac.compare_digest(digest, hashes[slot * 32:(slot + 1) * 32]):
            raise ValueError('verity block digest mismatch')
        digest = hashlib.sha256(salt + hashes).digest()
        child = block
    if not hmac.compare_digest(digest, root):
        raise ValueError('verity root digest mismatch')
    return data


def encode_root_descriptor(data_bytes, block_size, salt, root):
    """Encode the unsigned v1 BIP root descriptor; signing is a separate step.

    Fixed 384-byte big-endian encoding: magic; version/size; hash format,
    algorithm, filesystem, block size; data/tree lengths; root; salt length,
    padded salt; zero reserved bytes. No mutable path supplies trust identity.
    """
    _, _, tree_bytes = geometry(data_bytes, block_size)
    salt = checked_salt(salt)
    if type(root) is not bytes or len(root) != 32:
        raise ValueError('invalid root digest')
    return struct.pack('>8s6I2Q32sI256s44s', b'BIPROOT\0', 1, 384, 1, 1, 1,
        block_size, data_bytes, tree_bytes, root, len(salt), salt, bytes(44))


def build_image(data_fd, image_fd, data_bytes, block_size, salt, expected_sha256):
    """Create filesystem || hash-tree in an empty caller-owned regular file.

    expected_sha256 must identify the completed filesystem image selected by the
    caller's construction/receipt validation. This function checks copied bytes
    against that digest before building the tree from the private output copy.
    Inputs/output must remain quiescent and private. Memory is O(block_size).
    Failure leaves partial output for the caller to discard. Successful return
    is a root digest, not signing, fsync, atomic publication or boot qualification.
    """
    _, _, tree_bytes = geometry(data_bytes, block_size)
    salt = checked_salt(salt)
    if (type(expected_sha256) is not bytes or len(expected_sha256) != 32 or
            data_bytes > MAX_OFFSET - tree_bytes):
        raise ValueError('invalid expected image digest or combined extent')
    source, target = os.fstat(data_fd), os.fstat(image_fd)
    if (not stat.S_ISREG(source.st_mode) or not stat.S_ISREG(target.st_mode) or
            (source.st_dev, source.st_ino) == (target.st_dev, target.st_ino) or
            source.st_size != data_bytes or target.st_size != 0):
        raise ValueError('requires exact regular data file and empty distinct image')
    digest = hashlib.sha256()
    for offset in range(0, data_bytes, block_size):
        data = read_exact(data_fd, block_size, offset)
        digest.update(data)
        write_exact(image_fd, data, offset)
    if (os.fstat(data_fd).st_size != data_bytes or
            os.fstat(image_fd).st_size != data_bytes or
            not hmac.compare_digest(digest.digest(), expected_sha256)):
        raise ValueError('copied image does not match expected filesystem digest')
    return _write_tree(image_fd, image_fd, data_bytes, block_size, salt, data_bytes)


def verify_image(image_fd, data_bytes, block_size, salt, root, expected_sha256):
    """Check a private/quiescent combined image; return its whole-file SHA-256.

    Read data once and hash-tree bytes three times, without a full-image buffer
    or temporary tree. Memory is O(block_size). This is construction consistency,
    not signer authentication or a concurrent-storage integrity boundary.
    """
    counts, offsets, tree_bytes = geometry(data_bytes, block_size)
    salt = checked_salt(salt)
    if (type(root) is not bytes or len(root) != 32 or
            type(expected_sha256) is not bytes or len(expected_sha256) != 32 or
            data_bytes > MAX_OFFSET - tree_bytes):
        raise ValueError('invalid expected verity image binding')
    info = os.fstat(image_fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size != data_bytes + tree_bytes:
        raise ValueError('requires exact regular combined image')
    source_digest, combined_digest = hashlib.sha256(), hashlib.sha256()
    source_offset, source_blocks = 0, data_bytes // block_size
    fanout = block_size // 32
    for level, blocks in enumerate(counts):
        for block in range(blocks):
            expected = bytearray(block_size)
            first = block * fanout
            for slot in range(min(fanout, source_blocks - first)):
                data = read_exact(image_fd, block_size,
                                  source_offset + (first + slot) * block_size)
                if level == 0:
                    source_digest.update(data)
                    combined_digest.update(data)
                expected[slot * 32:(slot + 1) * 32] = hashlib.sha256(salt + data).digest()
            actual = read_exact(image_fd, block_size,
                                data_bytes + offsets[level] + block * block_size)
            if not hmac.compare_digest(actual, expected):
                raise ValueError('retained verity tree differs from filesystem bytes')
        source_offset, source_blocks = data_bytes + offsets[level], blocks
    if not hmac.compare_digest(source_digest.digest(), expected_sha256):
        raise ValueError('retained verity data differs from selected filesystem digest')
    actual_root = hashlib.sha256(salt + read_exact(image_fd, block_size, data_bytes)).digest()
    if not hmac.compare_digest(actual_root, root):
        raise ValueError('retained verity root differs from descriptor')
    # Physical tree order is root-first, unlike the bottom-up comparisons above.
    for offset in range(0, tree_bytes, block_size):
        combined_digest.update(read_exact(image_fd, block_size, data_bytes + offset))
    if os.fstat(image_fd).st_size != data_bytes + tree_bytes:
        raise ValueError('combined image size changed during validation')
    return combined_digest.hexdigest()
