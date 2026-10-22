#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run the actual libdtrace virtual-program transform against a built world."""
from pathlib import Path
import os
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
world = Path(sys.argv[2]).resolve()
if not out.is_relative_to('/usr/obj') or not world.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj for test output and the world object root')
out.mkdir(parents=True, exist_ok=True)
obj = world / root.relative_to('/') / 'amd64.amd64'
tmp = obj / 'tmp'
lib = obj / 'cddl/lib/libdtrace'
execinfo = obj / 'lib/libexecinfo'
if not (lib / 'libdtrace.so.2').exists():
    raise SystemExit('Build the matching world first')
if not (execinfo / 'libexecinfo.so.1').exists():
    raise SystemExit('Build the matching libexecinfo first')
program_source = root / 'cddl/contrib/opensolaris/lib/libdtrace/common/dt_program.c'
program_object = lib / 'dt_program.pico'
program_dep = lib / '.depend.dt_program.pico'
if (not program_object.exists() or not program_dep.exists() or
        str(program_source) not in program_dep.read_text() or
        program_object.stat().st_mtime_ns < program_source.stat().st_mtime_ns or
        (lib / 'libdtrace.so.2').stat().st_mtime_ns <
        program_object.stat().st_mtime_ns):
    raise SystemExit('libdtrace must be built from this source tree')

common = root / 'cddl/contrib/opensolaris/lib/libdtrace/common'
source = root / 'contrib/hypertrace/tests/vprog-transform.c'
binary = out / 'vprog-transform'
command = [
    'cc', '--sysroot=' + str(tmp), '-std=gnu17', '-fsanitize=address,undefined',
    '-Wall', '-Wextra',
    '-Werror', '-Wno-unknown-pragmas',
    '-I' + str(common),
    '-I' + str(root / 'cddl/contrib/opensolaris/lib/libctf/common'),
    '-I' + str(root / 'cddl/contrib/opensolaris/head'),
    '-I' + str(root / 'sys/cddl/compat/opensolaris'),
    '-I' + str(root / 'sys/cddl/contrib/opensolaris/uts/common'),
    str(source), '-L' + str(lib), '-L' + str(execinfo),
    '-Wl,-rpath,' + str(lib),
    '-ldtrace', '-o', str(binary),
]
compiled = subprocess.run(command, capture_output=True, text=True)
(out / 'build.log').write_text(compiled.stdout + compiled.stderr)
if compiled.returncode:
    raise SystemExit('vprog-transform build failed; inspect build.log')
env = os.environ.copy()
env['LD_LIBRARY_PATH'] = ':'.join((str(lib), str(execinfo),
    str(tmp / 'lib'), str(tmp / 'usr/lib')))
result = subprocess.run([str(binary)], env=env, capture_output=True,
                        text=True, timeout=30)
(out / 'run.log').write_text(result.stdout + result.stderr)
print(result.stdout, end='')
if result.returncode:
    raise SystemExit('vprog-transform failed; inspect run.log')
