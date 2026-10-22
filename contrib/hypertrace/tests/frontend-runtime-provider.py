#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Providers and probes (dt_provider.c) through a modelled dtrace(4) vector.

The vector answers DTRACEIOC_PROVIDER/PROBEMATCH/PROBES/PROBEARG from a fixed
probe table; frontend-runtime-shim.so stands in for /dev/dtrace/kinst.  No
device or kernel is used.  Built with ASan/UBSan and again with malloc fault
injection over probe discovery and USDT site definition.
"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import frontend_runtime_common as F

out, obj = F.setup('frontend-runtime-provider')
src = F.TESTS / 'frontend-runtime-provider.c'
shim_src = F.TESTS / 'frontend-runtime-shim.c'
shim = F.build(out, obj, shim_src, out / 'frontend-runtime-shim.so', ['-g', '-O1'],
               shared=True, libs=())
results = {}
for name, flags in (('asan', F.SANITIZE), ('faults', F.FAULTS)):
    exe = F.build(out, obj, src, out / f'frontend-runtime-provider-{name}', flags,
                  libs=('-ldtrace', '-lctf'))
    results[name] = F.run(out, exe, F.env_for(obj, shim), timeout=3000)
F.finish(out, obj, results, [src, shim_src, F.TESTS / 'frontend-runtime-shim.h',
         F.TESTS / 'frontend-faults.h'],
         'dt_provider.c via dtrace_vopen provider/probe ioctl model; kinst device via preloaded shim')
