#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production HyperTrace program-error path on long messages."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'cddl/contrib/opensolaris/lib/libdtrace/common/dt_error.c').read_text()
(out / 'prog-error.inc').write_text(source[source.index('void\ndt_set_progerr('):])
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.c')), '-o', str(out / 'prog-error-test')],
    check=True)
subprocess.run([str(out / 'prog-error-test')], check=True, timeout=30)
