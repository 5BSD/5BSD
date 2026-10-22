#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/dev/vmm/vmm_dev.c').read_text()
start = source.index('static int\nvmmdev_lookup_and_destroy_impl(')
end = source.index('static int\nsysctl_vmm_destroy(', start)
(out / 'destroy.inc').write_text(source[start:end])
start = source.index('\tcase VM_REINIT:\n\t\t/* Identity-checked')
end = source.index('\n\t\tbreak;', start)
(out / 'reset.inc').write_text(source[start + len('\tcase VM_REINIT:\n'):end])
start = source.index('static int\nvmmctl_ioctl(')
end = source.index('\nstatic struct cdev *vmmctl_cdev;', start)
(out / 'ioctl.inc').write_text(source[start:end])
header = (root / 'sys/dev/vmm/vmm_dev.h').read_text()
start = header.index('struct vmmctl_vm_create {')
end = header.index('#define\tVMMCTL_VM_CREATE', start)
(out / 'abi.inc').write_text(header[start:end])
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
    '-DMAC', '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.c')), '-o', str(out / 'identity')], check=True)
subprocess.run([str(out / 'identity')], check=True, timeout=30)
