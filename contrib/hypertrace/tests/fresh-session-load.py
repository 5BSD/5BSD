#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the actual snapshot trace-member loader without restoring a VM."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/snapshot.c').read_text()
start = source.index('static int\nload_hypertrace_transfer_fd(')
end = source.index('\nint\nload_restore_file(', start)
(out / 'fresh-session-load.inc').write_text(source[start:end])
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    '-I' + str(root / 'usr.sbin/bhyve'), '-I' + str(root / 'sys'),
    str(Path(__file__).with_suffix('.c')), '-lmd',
    '-o', str(out / 'fresh-session-load')], check=True)
subprocess.run([str(out / 'fresh-session-load')], check=True, timeout=30)
