# SPDX-License-Identifier: BSD-2-Clause
"""Copy an explicitly measured offline disk into private VM output storage."""
import hashlib
import os
from pathlib import Path
import re
import stat


def check_source(path, expected, size):
    if not isinstance(expected, str) or re.fullmatch('[0-9a-f]{64}', expected) is None:
        raise ValueError('disk source requires a lowercase SHA256')
    path = Path(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != size:
            raise ValueError('disk source must be a regular file of the selected capacity')
        if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
            raise ValueError('disk source SHA256 differs')
    return path.resolve(strict=True)


def copy_source(path, expected, size, destination):
    path = check_source(path, expected, size)
    # Exclusive creation also refuses an existing destination or symlink. Never
    # truncate a supplied file. A failed copy remains diagnostic output only.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != size:
            raise ValueError('disk source changed before copy')
        with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as target:
            measured = hashlib.sha256()
            remaining = size
            while remaining:
                data = source.read(min(1024 * 1024, remaining))
                if not data:
                    raise ValueError('disk source shortened during copy')
                target.write(data)
                measured.update(data)
                remaining -= len(data)
            if source.read(1) or measured.hexdigest() != expected:
                raise ValueError('disk source changed during copy')
            target.flush()
            os.fsync(target.fileno())
    check_source(path, expected, size)
    check_source(destination, expected, size)
    return path
