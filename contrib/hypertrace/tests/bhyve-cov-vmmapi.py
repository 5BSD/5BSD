#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""The actual libvmmapi.so (coverage build) against the vmm(4) model.

usage: bhyve-cov-vmmapi.py OUT LIBVMMAPI_DIR BUILD

Builds bhyve-cov-vmmfake.c as a shared object linked ahead of libc and
bhyve-cov-vmmapi.c against the build's libvmmapi.so.7, then runs it.  The
model refuses vmm ioctls on real descriptors and never loads modules.
"""
from pathlib import Path
import subprocess, sys

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parents[2]
out, libdir, build = (Path(p).resolve() for p in sys.argv[1:4])
if not out.is_relative_to('/usr/obj') or out.exists():
    raise SystemExit('Use a new /usr/obj output directory')
out.mkdir(parents=True)
flags = ['-I%s' % (build / 'source-includes'), '-I%s' % (ROOT / 'lib/libvmmapi'),
         '-I%s' % (ROOT / 'sys'), '-I%s' % TESTS, '-DWITH_VMMAPI_SNAPSHOT', '-std=gnu17',
         '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-g']
subprocess.run(['cc'] + flags + ['-O1', '-fPIC', '-shared', '-o', str(out / 'libvmmfake.so'),
                str(TESTS / 'bhyve-cov-vmmfake.c')], check=True)
subprocess.run(['cc'] + flags + ['-O0', '-o', str(out / 'vmmapi-test'),
                str(TESTS / 'bhyve-cov-vmmapi.c'), '-L%s' % out, '-lvmmfake',
                '-L%s' % libdir, '-lvmmapi', '-Wl,-rpath,%s:%s' % (out, libdir)], check=True)
done = subprocess.run([str(out / 'vmmapi-test')], cwd=out, capture_output=True, text=True,
                      timeout=600)
(out / 'run.log').write_text(done.stdout + done.stderr)
print(done.stdout + done.stderr)
raise SystemExit(done.returncode)
