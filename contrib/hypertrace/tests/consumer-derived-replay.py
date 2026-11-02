#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'cddl/contrib/opensolaris/cmd/dtrace/dtrace.c').read_text()
start = source.index('static int\nidentified_derived_parent_matches(')
end = source.index('\nstatic int\nreconnect_dtraced(', start)
(out / 'consumer-derived-replay.inc').write_text(source[start:end])
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-Wno-unknown-pragmas',
    '-UNDEBUG',
    '-fsanitize=address,undefined', '-I' + str(out),
    '-I' + str(root / 'usr.sbin/dtraced'), '-I' + str(root / 'sys'),
    '-I' + str(root / 'cddl/contrib/opensolaris/lib/libdtrace/common'),
    str(Path(__file__).with_suffix('.c')),
    str(root / 'cddl/contrib/opensolaris/lib/libdtrace/common/dt_list.c'),
    '-lcrypto',
    '-o', str(out / 'consumer-derived-replay')], check=True)
subprocess.run([str(out / 'consumer-derived-replay')], check=True, timeout=20)
