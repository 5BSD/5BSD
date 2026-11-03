# SPDX-License-Identifier: BSD-2-Clause
"""Independent SDK cache copies with optional filesystem copy offload.

No hardlinks or policy fallback: ordinary copies are used when offloading is
unavailable. All snapshot inventory/digest verification remains mandatory.
The functions are copytree file callbacks with explicit destination filenames.
"""
import errno
import os
import shutil
import stat


def copyfile(source, destination):
    """Copy SDK file bytes, allowing filesystem COW without sharing writes.

    copy_file_range permits FreeBSD/ZFS block cloning. Unsupported platforms or
    filesystems use the ordinary copy; storage and permission errors propagate.
    Snapshot hashing and source-before/after checks remain the caller's policy.
    """
    if os.path.exists(destination) and os.path.samefile(source, destination):
        raise shutil.SameFileError(source, destination, "source and destination are the same file")
    source_stat = os.stat(source)
    transfer = getattr(os, "copy_file_range", None)
    if not callable(transfer) or not stat.S_ISREG(source_stat.st_mode) or not source_stat.st_size:
        return shutil.copyfile(source, destination)
    try:
        with open(source, "rb") as reader, open(destination, "wb") as writer:
            remaining = source_stat.st_size
            while remaining:
                count = transfer(reader.fileno(), writer.fileno(), min(8 * 1024 * 1024, remaining))
                if not count:
                    # Some filesystems decline offloading by returning no data.
                    # Restart an ordinary copy; never accept a truncated copy.
                    break
                remaining -= count
            else:
                return destination
    except OSError as error:
        if error.errno not in {errno.ENOSYS, errno.EXDEV, errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
            raise
    return shutil.copyfile(source, destination)


def copy2(source, destination):
    """Copy SDK bytes independently and preserve the existing stat policy."""
    result = copyfile(source, destination)
    shutil.copystat(source, destination)
    return result
