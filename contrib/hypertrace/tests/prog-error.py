#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production HyperTrace program-error record and forward path."""
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
common = root / 'cddl/contrib/opensolaris/lib/libdtrace/common'
header = (common / 'dt_program.h').read_text()
length = re.search(r'^#define\s+DT_PROG_ERRLEN\s+(\S+)$', header, re.MULTILINE)
if length is None:
    raise SystemExit('Missing DT_PROG_ERRLEN')
source = (common / 'dt_error.c').read_text()
start = source.index('/*\n * Append "; reason" to dp_err.')
source.index('\nint\ndt_set_progerr(', start)
(out / 'prog-error.inc').write_text(source[start:])
scratch = out / 'tmp'
scratch.mkdir(exist_ok=True)
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
    '-fsanitize=address,undefined', '-DDT_PROG_ERRLEN=' + length.group(1),
    '-I' + str(out), str(Path(__file__).with_suffix('.c')),
    '-o', str(out / 'prog-error-test')], check=True)
subprocess.run([str(out / 'prog-error-test'), str(scratch)], check=True,
    timeout=30)
