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
source = (root / 'usr.sbin/bhyve/migration_session.c').read_text()
start = source.index('int\nmigration_prod_source_finish_intent(')
(out / 'intent.inc').write_text(source[source.index('/* The IPC controller owns this context'):source.index('static int\nprod_retire(')] + source[start:source.index('/* A recovery request cannot replace', start)])
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(root / 'sys'), '-I' + str(root / 'usr.sbin/bhyve'), '-I' + str(out),
    str(Path(__file__).with_suffix('.c')), '-Wl,--wrap=fsync', '-lmd',
    '-o', str(out / 'intent')], check=True)
subprocess.run([str(out / 'intent')], cwd=out, check=True, timeout=30)
