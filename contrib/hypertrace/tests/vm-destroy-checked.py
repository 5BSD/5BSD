#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run libvmmapi's actual checked destroy against a faulted control ioctl."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'lib/libvmmapi/vmmapi.c').read_text()
parts = []
for signature in ('int\nvm_destroy_request_checked(', 'int\nvm_destroy_identity_request_checked(', 'int\nvm_destroy_checked(', 'int\nvm_destroy_identity_checked(', 'int\nvm_destroy_name_identity_checked(', 'void\nvm_destroy('):
    start = source.index(signature)
    end = source.index('\n}', start) + 2
    parts.append(source[start:end])
(out / 'vm-destroy-checked.inc').write_text('\n\n'.join(parts) + '\n')
header = (root / 'sys/dev/vmm/vmm_dev.h').read_text()
start = header.index('struct vmmctl_vm_destroy_identity {')
(out / 'destroy-identity-abi.inc').write_text(header[start:header.index('\n};', start) + 3] + '\n')
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.c')),
    '-o', str(out / 'vm-destroy-checked-test')], check=True)
subprocess.run([str(out / 'vm-destroy-checked-test')], check=True, timeout=30)
