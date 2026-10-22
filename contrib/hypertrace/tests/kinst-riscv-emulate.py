#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Sanitize the actual RISC-V KINST emulator on a native host."""
from pathlib import Path
import os
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
tests = Path(__file__).resolve().parent
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/dev/kinst/riscv/kinst_isa.c').read_text()
start = source.index('#define _MATCH_REG')
end = source.index('#undef _MATCH_REG', start) + len('#undef _MATCH_REG')
match = re.search(r'static int\nkinst_emulate\(', source)
if match is None:
    raise SystemExit('Missing kinst_emulate')
emulate_end = source.index('\n}', match.start()) + 2
(out / 'kinst-riscv-functions.inc').write_text(
    source[start:end] + '\n\n' + source[match.start():emulate_end] + '\n')
binary = out / 'kinst-riscv-emulate-test'
subprocess.run([
    'cc', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
    '-fsanitize=address,undefined', '-I' + str(out),
    str(tests / 'kinst-riscv-emulate.c'), '-o', str(binary),
], check=True)
env = os.environ.copy()
for name in ('ASAN_OPTIONS', 'UBSAN_OPTIONS'):
    env[name] = (env.get(name, '') + ':' if env.get(name) else '') + \
        'halt_on_error=1'
subprocess.run([str(binary)], check=True, timeout=30, env=env)
