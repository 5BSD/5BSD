#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production TAP read path's V2 provenance decisions."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/net/if_tuntap.c').read_text()
start = source.index('static\tint\ntunread(')
end = source.index('\n}', start) + 2
(out / 'packet-v2-tunread.inc').write_text(source[start:end] + '\n')
binary = out / 'packet-v2-tunread'
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
    '-Wno-unused-parameter', '-UNDEBUG', '-fsanitize=address,undefined',
    '-I' + str(root / 'sys'), '-I' + str(out),
    str(Path(__file__).with_suffix('.c')), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
