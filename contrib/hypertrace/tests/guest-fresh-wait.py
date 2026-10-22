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
source = (root / 'usr.sbin/dtraced/dtraced_dttransport.cc').read_text()
start = source.index('bool\nwait_guest_fresh_prepare(')
end = source.index('\nvoid\nlisten_dttransport(', start)
(out / 'guest-fresh-wait.inc').write_text(source[start:end])
subprocess.run(['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out), '-I' + str(root / 'sys'),
    str(Path(__file__).with_suffix('.cc')), '-o', str(out / 'guest-fresh-wait')], check=True)
subprocess.run([str(out / 'guest-fresh-wait')], check=True, timeout=10)
