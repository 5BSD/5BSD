#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile the probe expansion with/without hooks using a prepared kernel tree."""

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, default=Path('/usr/src'))
    parser.add_argument('--kernel-obj', type=Path, required=True)
    parser.add_argument('--obj', type=Path,
                        default=Path('/usr/obj/5bsd-dtrace-third-validation/kernel'))
    args = parser.parse_args()
    src = args.src.resolve()
    kern = args.kernel_obj.resolve()
    out = args.obj.resolve()
    if not (kern / 'opt_global.h').is_file():
        parser.error('--kernel-obj must contain a configured kernel build')
    if '#define KDTRACE_HOOKS' not in (kern / 'opt_global.h').read_text():
        parser.error('the prepared kernel must enable KDTRACE_HOOKS')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'nohooks.h').write_text('#undef KDTRACE_HOOKS\n')

    core = ['sys/dev/acpica/acpi.c', 'sys/dev/iommu/busdma_iommu.c', 'sys/dev/iommu/iommu_gas.c', 'sys/fs/msdosfs/msdosfs_fat.c', 'sys/fs/msdosfs/msdosfs_vfsops.c', 'sys/fs/nfsclient/nfs_clstate.c', 'sys/fs/nfsserver/nfs_nfsdsocket.c', 'sys/fs/nfsserver/nfs_nfsdstate.c', 'sys/fs/tmpfs/tmpfs_subr.c', 'sys/fs/tmpfs/tmpfs_vnops.c', 'sys/opencrypto/crypto.c', 'sys/vm/swap_pager.c', 'sys/vm/vm_pageout.c']
    core += ['sys/kern/sys_process.c', 'sys/kern/sys_capability.c']
    core += [str(p.relative_to(src)) for p in sorted((src / 'sys/security/mac').glob('*.c'))]
    groups = [('kernel', kern, kern, core)]

    jobs = []
    for label, makepath, cwd, files in groups:
        if not cwd.is_dir():
            parser.error('missing prepared module object directory: ' + str(cwd))
        make = ['make', '-C', str(makepath)]
        if label != 'kernel':
            make += ['MAKEOBJDIR=' + str(cwd), 'KERNBUILDDIR=' + str(kern)]
        flags = shlex.split(subprocess.check_output(
            make + ['-V', '${CFLAGS}'], text=True))
        for name in files:
            source = src / name
            for enabled in (True, False):
                ident = label.replace('/', '_') + '-' + source.stem
                ident += '-hooks' if enabled else '-nohooks'
                command = ['cc', *flags, '-Werror']
                if source.name == 'linux_work.c':
                    command += [
                        '-I' + str(src / 'sys/compat/linuxkpi/common/include'),
                        '-I' + str(src / 'sys/compat/linuxkpi/dummy/include'),
                        '-include', str(src / 'sys/compat/linuxkpi/common/include'
                                        / 'linux/kconfig.h'),
                    ]
                if not enabled:
                    command += ['-include', str(out / 'nohooks.h')]
                command += ['-c', str(source), '-o', str(out / (ident + '.o'))]
                jobs.append((ident, command, cwd, source))

    def compile_one(job):
        ident, command, cwd, source = job
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
        (out / (ident + '.log')).write_text(
            shlex.join(command) + '\n' + result.stdout + result.stderr)
        unchanged = digest == hashlib.sha256(source.read_bytes()).hexdigest()
        status = result.returncode if unchanged else 1
        print(ident + ': ' + ('PASS' if status == 0 else 'FAIL'), flush=True)
        return dict(name=ident, status=status, command=command,
                    source_sha256=digest, source_unchanged=unchanged)

    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
        results = list(pool.map(compile_one, jobs))
    (out / 'compile-results.json').write_text(json.dumps(results, indent=2) + '\n')
    return int(any(result['status'] for result in results))


if __name__ == '__main__':
    raise SystemExit(main())
