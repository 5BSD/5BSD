#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the kernel V2 stamp functions with the real SipHash code."""
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
for signature in ('static uint64_t\nmbufid_v2_mac(',
                  'int\nmbufid_v2_stamp(',
                  'int\nmbufid_v2_verify(',
                  'int\nmbufid_v2_make_host('):
    start = source.index(signature)
    end = source.index('\n}', start) + 2
    parts.append(source[start:end])
(out / 'packet-v2-auth.inc').write_text('\n\n'.join(parts) + '\n')
siphash = out / 'siphash.o'
subprocess.run(['cc', '-std=gnu17', '-Werror', '-Wno-incompatible-library-redeclaration',
    '-Wno-implicit-function-declaration', '-include', 'stdbool.h',
    '-I' + str(root / 'sys'), '-c', str(root / 'sys/crypto/siphash/siphash.c'),
    '-o', str(siphash)], check=True)
binary = out / 'packet-v2-auth'
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
    '-fsanitize=address,undefined', '-I' + str(root / 'sys'), '-I' + str(out),
    str(Path(__file__).with_suffix('.c')), str(siphash), '-o', str(binary)],
    check=True)
subprocess.run([str(binary)], check=True, timeout=30)
