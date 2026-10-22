#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production guest and host kernel stack action arms."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('\t\t\tcase DTRACEACT_STACK:\n\t\t\t\tif (!dtrace_priv_kernel(state))')
end = source.index('\n\t\t\tcase DTRACEACT_PRINTIMMSTACK:', start)
header = (root / 'sys/sys/hypertrace.h').read_text()
helper_start = header.index('static __inline int\nhypertrace_pcstack_valid(')
helper_end = header.index('\n}', helper_start) + 2
fixture = Path(__file__).with_suffix('.c').read_text()
fixture = fixture.replace('/* PCSTACK_HELPER */', header[helper_start:helper_end], 1)
fixture = fixture.replace('/* PRODUCTION_ARM */', source[start:end], 1)
path = out / 'guest-pcstack-action.c'
path.write_text(fixture)
binary = out / 'guest-pcstack-action'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(path), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
