#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the kernel V1-to-V2 persistent-tag upgrade and failure path."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/kern/uipc_mbuf.c').read_text()
start = source.index('struct mbufid_v2_tag {')
parts = [source[start:source.index('};', start) + 2]]
for signature in ('mbufid_t *\nm_mbufid(', 'mbufid_t *\nm_mbufid_ensure(',
                  'mbufid_v2_t *\nm_mbufid_v2(',
                  'uint64_t\nm_mbufid_v2_local_epoch(',
                  'void\nm_mbufid_v2_local_epoch_set(',
                  'mbufid_v2_t *\nm_mbufid_v2_ensure('):
    start = source.index(signature)
    end = source.index('\n}', start) + 2
    parts.append(source[start:end])
(out / 'packet-v2-sidecar.inc').write_text('\n\n'.join(parts) + '\n')
binary = out / 'packet-v2-sidecar'
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
    '-fsanitize=address,undefined', '-I' + str(root / 'sys'), '-I' + str(out),
    str(Path(__file__).with_suffix('.c')), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
