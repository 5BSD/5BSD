#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the real restore coordinator with a fresh-session boundary fixture."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/snapshot.c').read_text()
start = source.index('int\nvm_restore_transaction(')
end = source.index('\nstatic int\nsnapshot_write_all(', start)
(out / 'fresh-session-restore.inc').write_text(source[start:end])
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
    '-Wno-unused-variable', '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.c')), '-o', str(out / 'restore')], check=True)
subprocess.run([str(out / 'restore')], check=True, timeout=30)
