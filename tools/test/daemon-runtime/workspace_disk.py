# SPDX-License-Identifier: BSD-2-Clause
"""Explicit extra disk for disposable build work; never reformat a source disk."""
import os
from pathlib import Path

MIB = 1024 * 1024


def requirement(capacity_mib, input_present, output_mib, root_mib, reserve_mib):
    if type(capacity_mib) is not int or capacity_mib < 0:
        raise ValueError('workspace capacity must be an integer')
    if not capacity_mib:
        return 0
    if not input_present or not output_mib or not 16 <= capacity_mib <= 65536:
        raise ValueError('workspace disk requires input/output disks and 16..65536 MiB capacity')
    if type(reserve_mib) is not int or not 0 <= reserve_mib <= 65536:
        raise ValueError('workspace host reserve must be 0..65536 MiB')
    # Root UFS and its GPT disk coexist. Existing source disks are already charged
    # to available host space; the private output copy must be charged again.
    return (capacity_mib + output_mib + 2 * root_mib + reserve_mib) * MIB


def check_space(work, required_bytes):
    if not required_bytes:
        return None
    parent = Path(work).parent
    while not parent.exists():
        parent = parent.parent
    info = os.statvfs(parent)
    available = info.f_bavail * info.f_frsize
    if available < required_bytes:
        raise ValueError('insufficient host disk budget for private VM disks and reserve')
    return {'filesystem': str(parent.resolve()), 'available_bytes': available,
            'required_bytes': required_bytes,
            'scope': 'preflight observation; not a reservation against concurrent writers'}


def create(path, capacity_mib):
    if type(capacity_mib) is not int or not 16 <= capacity_mib <= 65536:
        raise ValueError('workspace capacity must be 16..65536 MiB')
    # Exclusive creation rejects symlinks and files; sparse zeros avoid a large
    # RAM buffer. It remains a disk image and is attached by a block device.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.ftruncate(stream.fileno(), capacity_mib * MIB)
        os.fsync(stream.fileno())
