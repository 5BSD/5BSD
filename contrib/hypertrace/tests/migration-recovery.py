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
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(root / 'sys'),
    '-I' + str(root / 'usr.sbin/bhyve'),
    str(Path(__file__).with_suffix('.c')), '-Wl,--wrap=fsync', '-lmd',
    '-o', str(out / 'recovery')], check=True)
subprocess.run([str(out / 'recovery')], cwd=out, check=True, timeout=30)
