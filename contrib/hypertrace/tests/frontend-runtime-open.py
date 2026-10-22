#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""dtrace_open/vopen/fdopen/close (dt_open.c) offline.

frontend-runtime-shim.so is preloaded so /dev/dtrace paths, kldload, modfind
and the provider/bootfile sysctls are scripted; the real device and kernel
linker are never used.  Built with ASan/UBSan and again with malloc fault
injection over the whole of dtrace_open().
"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import frontend_runtime_common as F

out, obj = F.setup('frontend-runtime-open')
src = F.TESTS / 'frontend-runtime-open.c'
shim_src = F.TESTS / 'frontend-runtime-shim.c'
shim = F.build(out, obj, shim_src, out / 'frontend-runtime-shim.so', ['-g', '-O1'],
               shared=True, libs=())
results = {}
for name, flags in (('asan', F.SANITIZE), ('faults', F.FAULTS)):
    exe = F.build(out, obj, src, out / f'frontend-runtime-open-{name}', flags,
                  libs=('-ldtrace', '-lctf'))
    results[name] = F.run(out, exe, F.env_for(obj, shim), timeout=3000)
F.finish(out, obj, results, [src, shim_src, F.TESTS / 'frontend-runtime-shim.h',
         F.TESTS / 'frontend-faults.h'],
         'dt_open.c entry points; device, kldload and sysctls scripted by a preloaded shim')
