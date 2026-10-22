#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the exact kernel VM-epoch publication and reuse checks."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/kern/uipc_mbuf.c').read_text()
parts = []
for signature in ('void\nmbufid_v2_vm_epoch_publish(',
                  'void\nmbufid_v2_vm_epoch_revoke(',
                  'int\nmbufid_v2_vm_epoch_current('):
    start = source.index(signature)
    end = source.index('\n}', start) + 2
    parts.append(source[start:end])
(out / 'packet-v2-epoch.inc').write_text('\n\n'.join(parts) + '\n')
binary = out / 'packet-v2-epoch'
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
    '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.c')), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
