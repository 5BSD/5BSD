# SPDX-License-Identifier: BSD-2-Clause
"""Stage ZFS mechanism-test prerequisites from explicit world/kernel inputs.

This small fixture is not package-derived installed-system qualification.
Dependencies are read from ELF metadata, never resolved using host libraries.
"""
import hashlib
import re
import shutil
import subprocess
from pathlib import Path


def stage_zfs(root, kernel_dir, stage):
    hashes = {}
    seen = set()

    def copy(source, relative):
        source = source.resolve(strict=True)
        if not (source.is_relative_to(root) or source.is_relative_to(kernel_dir)):
            raise ValueError('ZFS input escapes selected roots: ' + str(source))
        digest = hashlib.file_digest(source.open('rb'), 'sha256').hexdigest()
        dest = stage / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
        if any(hashlib.file_digest(p.open('rb'), 'sha256').hexdigest() != digest
               for p in (source, dest)):
            raise ValueError('ZFS input changed during copy: ' + str(source))
        hashes[str(source)] = digest

    def elf(relative):
        if relative in seen:
            return
        seen.add(relative)
        source = root / relative
        copy(source, relative)
        headers = subprocess.check_output(['readelf', '-l', str(source)], text=True)
        for interpreter in re.findall(r'Requesting program interpreter: ([^\]]+)', headers):
            elf(interpreter.lstrip('/'))
        dynamic = subprocess.check_output(['readelf', '-d', str(source)], text=True)
        if re.search(r'\((?:RPATH|RUNPATH)\)', dynamic):
            raise ValueError('unsupported ZFS fixture runtime search path')
        for library in re.findall(r'\(NEEDED\).*\[([^\]]+)\]', dynamic):
            if '/' in library:
                raise ValueError('unsupported dependency path')
            matches = [str(Path(d) / library) for d in ('lib', 'usr/lib')
                       if (root / d / library).is_file()]
            if len(matches) != 1:
                raise ValueError('missing or ambiguous staged library: ' + library)
            elf(matches[0])

    for program in ('bin/sh', 'sbin/zpool', 'sbin/zfs', 'usr/bin/truncate'):
        elf(program)
    # KLD comes from the same selected kernel build, not an installed host module.
    copy(kernel_dir / 'modules/usr/src/sys/modules/zfs/zfs.ko', 'boot/kernel/zfs.ko')
    (stage / 'etc/zfs').mkdir(parents=True, exist_ok=True)
    return hashes
