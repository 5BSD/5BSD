#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production HyperTrace program-error record and forward path."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

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
# A new directory each run: a file left by a failed run must not fail the next.
scratch = Path(tempfile.mkdtemp(prefix='tmp.', dir=out))
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
    '-fsanitize=address,undefined', '-DDT_PROG_ERRLEN=' + length.group(1),
    '-I' + str(out), str(Path(__file__).with_suffix('.c')),
    '-o', str(out / 'prog-error-test')], check=True)
# The errors under test are printed on stderr.  Keep them off the terminal,
# but show the end of them, where a failed assertion is, when the test fails.
log = out / 'prog-error.stderr'
try:
    with log.open('w') as stderr:
        status = subprocess.run([str(out / 'prog-error-test'), str(scratch)],
            stderr=stderr, timeout=30).returncode
except subprocess.TimeoutExpired:
    status = 'timed out'
if status != 0:
    sys.stderr.write(log.read_text(errors='replace')[-2000:])
    raise SystemExit(f'prog-error-test: status {status}; stderr is in {log}')
