#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Sanitize the actual arm64 KINST classifier and emulator on a native host."""
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
source = (root / 'sys/cddl/dev/kinst/aarch64/kinst_isa.c').read_text()


def function(name):
    match = re.search(r'static [^\n]+\n' + name + r'\(', source)
    if match is None:
        raise SystemExit('Missing function: ' + name)
    end = source.index('\n}', match.start()) + 2
    return source[match.start():end]


names = ('kinst_instr_type', 'kinst_reg_read', 'kinst_reg_write',
         'kinst_emulate')
(out / 'kinst-arm64-functions.inc').write_text(
    '\n\n'.join(function(name) for name in names) + '\n')
binary = out / 'kinst-arm64-emulate-test'
subprocess.run([
    'cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(out),
    '-I' + str(root / 'sys/cddl/dev/kinst/aarch64'),
    str(tests / 'kinst-arm64-emulate.c'), '-o', str(binary),
], check=True)
env = os.environ.copy()
for name in ('ASAN_OPTIONS', 'UBSAN_OPTIONS'):
    env[name] = (env.get(name, '') + ':' if env.get(name) else '') + \
        'halt_on_error=1'
subprocess.run([str(binary)], check=True, timeout=30, env=env)
