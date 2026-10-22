#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/sys/dtrace.h').read_text()
a = source.index('typedef struct dtrace_difo {'); b = source.index('} dtrace_difo_t;', a) + len('} dtrace_difo_t;')
(out / 'difo-types.inc').write_text(source[a:b])
source = (root / 'cddl/contrib/opensolaris/lib/libdtrace/common/dt_subr.c').read_text()
a = source.index('void\ndt_difo_free('); b = source.index('\n}\n', source.index('dt_difo_dup(', a)) + 3
(out / 'difo-ownership.inc').write_text(source[a:b])
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(out), str(Path(__file__).with_suffix('.c')), '-o', str(out / 'test')], check=True)
subprocess.run([str(out / 'test')], check=True, timeout=30)
