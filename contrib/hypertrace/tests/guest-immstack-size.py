#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production immediate-stack size contract."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
functions = []
for name in ('dtrace_immstack_record_size', 'dtrace_stack_record_size',
    'dtrace_ustack_record_size'):
    start = source.index('static int\n' + name + '(')
    end = source.index('\n}', start) + 2
    functions.append(source[start:end])
(out / 'guest-immstack-size.inc').write_text('\n\n'.join(functions) + '\n')
binary = out / 'guest-immstack-size'
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.c')), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
