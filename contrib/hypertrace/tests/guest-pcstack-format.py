#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Prove raw guest stack PCs never use host kernel symbol lookup."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'cddl/contrib/opensolaris/lib/libdtrace/common/dt_consume.c').read_text()
start = source.index('int\ndt_print_stack(')
end = source.index('\n}', start) + 2
header = (root / 'sys/sys/hypertrace.h').read_text()
macros_start = header.index('#define HYPERTRACE_STACK_GUEST_TAG')
macros_end = header.index('/* USTACK', macros_start)
fixture = Path(__file__).with_suffix('.c').read_text()
fixture = fixture.replace('/* STACK_MACROS */',
    header[macros_start:macros_end], 1)
fixture = fixture.replace('/* PRODUCTION_FORMATTER */', source[start:end], 1)
path = out / 'guest-pcstack-format.c'
path.write_text(fixture)
binary = out / 'guest-pcstack-format'
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(path), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
