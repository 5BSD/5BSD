#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run arm64 and RISC-V DTrace user-stack implementations with ABI frames."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
for arch in ('aarch64', 'riscv'):
    source = (root / f'sys/cddl/dev/dtrace/{arch}/dtrace_isa.c').read_text()
    def section(start, end):
        return source[source.index(start):source.index(end, source.index(start))]
    extracted = (
        section('static int\ndtrace_getustack_common(',
                '\nvoid\ndtrace_getupcstack(') +
        section('int\ndtrace_getustackdepth(',
                '\nvoid\ndtrace_getufpstack(') +
        section('void\ndtrace_getufpstack(',
                '\nuint64_t\ndtrace_getarg(') +
        section('uint64_t\ndtrace_getarg(',
                '\nint\ndtrace_getstackdepth('))
    (out / f'provider-userstack-{arch}.inc').write_text(extracted)
    binary = out / f'provider-userstack-{arch}'
    subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
        '-fsanitize=address,undefined', '-I' + str(out),
        '-DTEST_ARM64=' + ('1' if arch == 'aarch64' else '0'),
        str(Path(__file__).with_suffix('.c')),
        '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
