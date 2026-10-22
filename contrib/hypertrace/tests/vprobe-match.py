#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production cross-VM DTrace enabling callback."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('static int\ndtrace_ecb_create_enable(')
end = source.index('\nstatic dtrace_ecb_t *\ndtrace_epid2ecb(', start)
fixture = Path(__file__).with_suffix('.c').read_text()
fixture = fixture.replace('/* PRODUCTION_MATCH */', source[start:end], 1)
path = out / 'vprobe-match.c'
path.write_text(fixture)
binary = out / 'vprobe-match'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(path), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
