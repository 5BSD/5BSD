#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Option handling (dt_options.c) against documented option semantics.

Builds frontend-runtime-options.c with ASan/UBSan and again with malloc fault
injection (-DWITH_FAULTS, no sanitizers).  Kernel option loading goes through
a dtrace_vopen() vector modelling DTRACEIOC_DOFGET; no device is opened.
The harness replaces abort() so the "core" option's exit handler finishes
the child normally instead of dumping core.
"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import frontend_runtime_common as F

out, obj = F.setup('frontend-runtime-options')
src = F.TESTS / 'frontend-runtime-options.c'
results = {}
for name, flags in (('asan', F.SANITIZE), ('faults', F.FAULTS)):
    d = out / name
    d.mkdir()
    exe = F.build(out, obj, src, out / f'frontend-runtime-options-{name}', flags,
                  libs=('-ldtrace', '-lctf'))
    results[name] = F.run(out, exe, F.env_for(obj), args=[d])
F.finish(out, obj, results, [src, F.TESTS / 'frontend-faults.h'],
         'dtrace_setopt/getopt, #pragma option context, DOFGET via vopen vector; offline')
