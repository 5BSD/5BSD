#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Durable destination image/successor/lock tests; no VM, device or daemon."""
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(root / 'sys'), '-I' + str(root / 'usr.sbin/bhyve'),
    '-I' + str(Path(__file__).parent),
    str(Path(__file__).with_suffix('.c')),
    '-Wl,--wrap=fsync,--wrap=renameat,--wrap=write',
    '-lmd', '-o', str(out / 'dest-image')], check=True)
subprocess.run([str(out / 'dest-image')], cwd=out, check=True, timeout=120)
