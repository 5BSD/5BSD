# SPDX-License-Identifier: BSD-2-Clause
"""Content binding for exclusive qualification disks, not root-resistant storage."""
import hashlib
import re


def disk_digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require_disk(path, expected):
    if not isinstance(expected, str) or re.fullmatch(r'[0-9a-f]{64}', expected) is None:
        raise ValueError('installed disk evidence lacks a valid SHA-256 binding; rerun installation')
    actual = disk_digest(path)
    if actual != expected:
        raise ValueError('installed disk changed since the preceding qualification stage')
    return actual
