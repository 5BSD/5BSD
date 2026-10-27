# SPDX-License-Identifier: BSD-2-Clause
"""Unsigned image/descriptor construction and retained-artifact consistency."""
import hashlib
import errno
import importlib.util
import os
from pathlib import Path
import re
import stat

spec = importlib.util.spec_from_file_location('verity_tree', Path(__file__).with_name('verity_tree.py'))
tree = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tree)


def policy(value):
    if (type(value) is not dict or set(value) != {'format', 'block_size', 'salt_hex'}
            or type(value['format']) is not int or value['format'] != 1
            or type(value['block_size']) is not int
            or type(value['salt_hex']) is not str
            or re.fullmatch(r'(?:[0-9a-f]{2}){0,256}', value['salt_hex']) is None):
        raise ValueError('invalid verity image policy')
    tree.geometry(2 * value['block_size'], value['block_size'])
    return dict(value)


def makefs_options(selected):
    # Align the complete image, without changing the filesystem sector size.
    return [] if selected is None else ['-R', str(policy(selected)['block_size'])]


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('verity artifact must be a regular nonsymlink file')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def build(folder, selected, source_sha256, source_bytes):
    """Caller owns the private/quiescent directory and publishes its receipt."""
    selected = policy(selected)
    folder = Path(folder)
    source = folder / 'system.ufs'
    if (not re.fullmatch(r'[0-9a-f]{64}', source_sha256)
            or source.is_symlink() or not source.is_file()):
        raise ValueError('invalid selected filesystem image')
    combined = folder / 'system.verity'
    descriptor = folder / 'root.descriptor'
    with source.open('rb') as src, combined.open('x+b') as target:
        os.chmod(combined, 0o600)
        root = tree.build_image(src.fileno(), target.fileno(), source_bytes,
            selected['block_size'], bytes.fromhex(selected['salt_hex']),
            bytes.fromhex(source_sha256))
    wire = tree.encode_root_descriptor(source_bytes, selected['block_size'],
        bytes.fromhex(selected['salt_hex']), root)
    with descriptor.open('xb') as stream:
        os.chmod(descriptor, 0o600)
        stream.write(wire)
    return dict(format=1, policy=selected, source_image_sha256=source_sha256,
        data_bytes=source_bytes, root_sha256=root.hex(),
        image_bytes=combined.stat().st_size, image_sha256=digest(combined),
        descriptor_sha256=digest(descriptor))


def verify(folder, value, selected, source_sha256, source_bytes):
    return verify_paths(Path(folder)/'system.verity', Path(folder)/'root.descriptor',
                        value, selected, source_sha256, source_bytes)


def _opened_artifact(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.EMLINK):
            raise ValueError('verity artifact must not be a symlink') from error
        raise
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError('verity artifact must be a regular file')
    return os.fdopen(fd, 'rb')


def verify_paths(combined, descriptor, value, selected, source_sha256, source_bytes):
    """Retained-byte consistency, not release authentication or fresh FS readback."""
    combined, descriptor = Path(combined), Path(descriptor)
    selected = policy(selected)
    if type(value) is not dict or set(value) != {'format', 'policy',
            'source_image_sha256', 'data_bytes', 'root_sha256', 'image_bytes',
            'image_sha256', 'descriptor_sha256'}:
        raise ValueError('invalid verity artifact receipt')
    if (type(value['format']) is not int or value['format'] != 1 or value['policy'] != selected
            or value['source_image_sha256'] != source_sha256
            or value['data_bytes'] != source_bytes
            or type(value['root_sha256']) is not str
            or re.fullmatch(r'[0-9a-f]{64}', value['root_sha256']) is None):
        raise ValueError('verity receipt differs from selected image/policy')
    _, _, tree_bytes = tree.geometry(source_bytes, selected['block_size'])
    # Open once: hash and tree consistency refer to the same retained object.
    with _opened_artifact(combined) as stream:
        combined_digest = tree.verify_image(stream.fileno(), source_bytes, selected['block_size'],
            bytes.fromhex(selected['salt_hex']), bytes.fromhex(value['root_sha256']),
            bytes.fromhex(source_sha256))
    with _opened_artifact(descriptor) as stream:
        wire = stream.read(385)
    if (combined_digest != value['image_sha256']
            or value['image_bytes'] != source_bytes + tree_bytes
            or len(wire) != 384
            or hashlib.sha256(wire).hexdigest() != value['descriptor_sha256']):
        raise ValueError('retained verity artifact differs from receipt')
    expected = tree.encode_root_descriptor(source_bytes, selected['block_size'],
        bytes.fromhex(selected['salt_hex']), bytes.fromhex(value['root_sha256']))
    if wire != expected:
        raise ValueError('root descriptor differs from selected artifact')
