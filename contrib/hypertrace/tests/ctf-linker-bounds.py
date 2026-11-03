#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the current libdtrace CTF relocation against its built library."""
from pathlib import Path
import os
import subprocess
import sys

native = len(sys.argv) == 4 and sys.argv[3] == '--native'
if len(sys.argv) != 3 and not native:
    raise SystemExit('usage: ctf-linker-bounds.py /usr/obj/results /usr/obj/world-root [--native]')
root = Path(__file__).resolve().parents[3]
out, world = (Path(arg).resolve() for arg in sys.argv[1:3])
if not all(path.is_relative_to('/usr/obj') for path in (out, world)):
    raise SystemExit('Use /usr/obj for validation artifacts')
out.mkdir(parents=True, exist_ok=True)
obj = world / root.relative_to('/') / 'amd64.amd64'
tmp = obj / 'tmp'
lib = obj / 'cddl/lib/libdtrace'
execinfo = obj / 'lib/libexecinfo'
source = root / 'cddl/contrib/opensolaris/lib/libdtrace/common/dt_hypertrace_linker.cc'
object_file = lib / 'dt_hypertrace_linker.pico'
dep = lib / '.depend.dt_hypertrace_linker.pico'
library = lib / 'libdtrace.so.2'
if (not native and not tmp.exists()) or not all(path.exists() for path in (object_file, dep, library)) or \
        str(source) not in dep.read_text() or \
        object_file.stat().st_mtime_ns < source.stat().st_mtime_ns or \
        library.stat().st_mtime_ns < object_file.stat().st_mtime_ns:
    raise SystemExit('Build libdtrace from the current source first')

common = root / 'cddl/contrib/opensolaris/lib/libdtrace/common'
command = [
    'c++', *([] if native else ['--sysroot=' + str(tmp)]), '-std=c++20',
    '-fsanitize=address,undefined', '-Wall', '-Wextra', '-Werror',
    '-Wno-unknown-pragmas',
    '-I' + str(world / 'source-includes'),
    '-I' + str(root / 'sys'),
    '-I' + str(common),
    '-I' + str(root / 'cddl/contrib/opensolaris/lib/libctf/common'),
    '-I' + str(root / 'cddl/contrib/opensolaris/common/ctf'),
    '-I' + str(root / 'cddl/contrib/opensolaris/head'),
    '-I' + str(root / 'sys/cddl/compat/opensolaris'),
    '-I' + str(root / 'cddl/compat/opensolaris/include'),
    '-I' + str(root / 'sys/cddl/contrib/opensolaris/uts/common'),
    str(root / 'contrib/hypertrace/tests/ctf-linker-bounds.cc'),
    '-L' + str(lib), '-L' + str(execinfo),
    '-Wl,-rpath,' + str(lib), '-ldtrace', '-lctf', '-o', str(out / 'ctf-linker-bounds'),
]
build = subprocess.run(command, capture_output=True, text=True)
(out / 'build.log').write_text(build.stdout + build.stderr)
if build.returncode:
    raise SystemExit('CTF linker fixture compilation failed; inspect build.log')
env = os.environ.copy()
env['LD_LIBRARY_PATH'] = ':'.join((str(lib), str(execinfo),
    str(obj / 'cddl/lib/libctf'), str(obj / 'lib/libproc'),
    str(obj / 'lib/librtld_db'), str(tmp / 'lib'), str(tmp / 'usr/lib')))
test = subprocess.run([str(out / 'ctf-linker-bounds')], env=env,
                      capture_output=True, text=True, timeout=30)
(out / 'run.log').write_text(test.stdout + test.stderr)
if test.returncode:
    raise SystemExit('CTF linker fixture failed; inspect run.log')
print('PASS: CTF offsets, member preflight, diagnostics, DIF index bounds, and allocation failure recovery')
