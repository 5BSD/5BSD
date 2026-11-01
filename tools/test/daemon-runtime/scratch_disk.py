# SPDX-License-Identifier: BSD-2-Clause
"""Bound a newly created private sparse guest disk; never operate on host devices."""
import json
import math
import os
from pathlib import Path
import shutil
import stat

MIB = 1024 ** 2


def policy(size_mib, allocated_mib, reserve_mib, parent, *, require_budget=True):
    if any(type(v) is not int for v in (size_mib, allocated_mib, reserve_mib)):
        raise ValueError('scratch sizes must be integers')
    if not size_mib:
        if allocated_mib:
            raise ValueError('scratch allocation budget requires a scratch disk')
        return None
    if not 128 <= size_mib <= 65536:
        raise ValueError('scratch logical capacity must be 128..65536 MiB')
    if not 0 <= allocated_mib <= size_mib or require_budget and not allocated_mib:
        raise ValueError('independent scratch disk requires an allocation budget within its logical capacity')
    if reserve_mib < 256:
        raise ValueError('scratch host reserve must be at least 256 MiB')
    parent = Path(parent)
    while not parent.exists():
        parent = parent.parent
    free = shutil.disk_usage(parent).free
    if allocated_mib and free < (allocated_mib + reserve_mib) * MIB:
        raise ValueError('scratch allocation budget plus reserve exceeds current host free space')
    return {'logical_bytes': size_mib*MIB, 'max_allocated_bytes': allocated_mib*MIB,
            'minimum_host_free_bytes': reserve_mib*MIB, 'host_free_before_bytes': free}


def create(path, capacity):
    path = Path(path)
    if not path.resolve().is_relative_to('/usr/obj'):
        raise ValueError('private scratch disk must use /usr/obj')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.ftruncate(fd, capacity)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('private scratch disk must be regular')
        return (info.st_dev, info.st_ino)
    finally:
        os.close(fd)


class DiskMonitor:
    def __init__(self, path, budget, report):
        self.path, self.budget = Path(path), budget
        self.identity = (self.path.stat().st_dev, self.path.stat().st_ino)
        self.stream = report.open('x')
        self.samples, self.maximum, self.minimum_free = 0, 0, None

    def observe(self, elapsed):
        if not math.isfinite(elapsed) or elapsed < 0:
            raise ValueError('invalid scratch resource sample time')
        info = self.path.lstat()
        if (not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != self.identity
                or info.st_size != self.budget['logical_bytes']):
            raise ValueError('private scratch disk identity or logical capacity changed')
        allocated = info.st_blocks * 512
        free = shutil.disk_usage(self.path.parent).free
        self.samples += 1
        self.maximum = max(self.maximum, allocated)
        self.minimum_free = free if self.minimum_free is None else min(self.minimum_free, free)
        self.stream.write(json.dumps({'elapsed_seconds': elapsed, 'allocated_bytes': allocated,
                                      'logical_bytes': info.st_size, 'host_free_bytes': free}) + '\n')
        self.stream.flush()
        if self.budget['max_allocated_bytes'] and allocated > self.budget['max_allocated_bytes']:
            raise ValueError('private scratch disk exceeds explicit host allocation budget')
        if free < self.budget['minimum_host_free_bytes']:
            raise ValueError('private scratch disk host free-space reserve exhausted')

    def close(self):
        self.stream.close()
        return dict(self.budget, samples=self.samples, max_observed_allocated_bytes=self.maximum,
                    minimum_observed_host_free_bytes=self.minimum_free,
                    scope='sampled private disk st_blocks and host filesystem free space; not complete I/O or peak accounting')
