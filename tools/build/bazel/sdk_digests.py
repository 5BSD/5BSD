# SPDX-License-Identifier: BSD-2-Clause
"""Bounded full-content SHA-256 verification; every selected file is read."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
from itertools import islice
import os
from pathlib import Path
import time


def _hash_file(path):
    with path.open('rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        value = hashlib.file_digest(stream, 'sha256').hexdigest()
    return value, size


def verify(expected, *, jobs, prefix, root=None):
    """Verify an ordered digest mapping, optionally below a snapshot root.

    The worker pool and submitted batches are bounded by jobs. Results are
    checked in manifest order so concurrent hashing preserves deterministic
    failure reporting. No mtime, inode or previous-run digest cache is used.
    Logical bytes count each verified manifest entry, including aliases; they
    do not measure physical disk traffic. A failure returns no success metrics.
    """
    if type(jobs) is not int or jobs < 1:
        raise ValueError('positive verification jobs required')
    paths = []
    for name, value in expected.items():
        path = Path(name)
        if root is not None:
            if path.is_absolute() or '..' in path.parts:
                raise ValueError(prefix + name)
            path = root / path
        paths.append((name, path, value))
    workers = min(jobs, len(paths))
    start = time.monotonic()
    total = 0

    def checked(items, results):
        nonlocal total
        for (name, _path, expected_hash), (actual, size) in zip(items, results, strict=True):
            if actual != expected_hash:
                raise ValueError(prefix + name)
            total += size

    if workers <= 1:
        checked(paths, map(_hash_file, (path for _, path, _ in paths)))
    else:
        pending = iter(paths)
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='bsd-sdk-hash') as pool:
            while batch := list(islice(pending, workers * 2)):
                checked(batch, pool.map(_hash_file, (path for _, path, _ in batch)))
    return dict(files=len(paths), logical_bytes=total, workers=workers,
                elapsed_seconds=time.monotonic() - start)
