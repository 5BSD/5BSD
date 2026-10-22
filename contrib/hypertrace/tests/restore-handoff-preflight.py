#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production restore handoff cut without a live VM."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/snapshot.c').read_text()
start = source.index('static int\nhypertrace_restore_prepare_handoff(')
end = source.index('\nint\nvm_restore_transaction(', start)
fixture = Path(__file__).with_suffix('.c').read_text()
fixture = fixture.replace('/* PRODUCTION_PREFLIGHT */', source[start:end], 1)
path = out / 'restore-handoff-preflight.c'
path.write_text(fixture)
binary = out / 'restore-handoff-preflight'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(path), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
