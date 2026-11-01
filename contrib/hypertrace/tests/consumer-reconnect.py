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
lib = root / 'cddl/contrib/opensolaris/lib/libdtrace/common'
library = (lib / 'dt_subr.c').read_text()
command = (root / 'cddl/contrib/opensolaris/cmd/dtrace/dtrace.c').read_text()
a = library.index('static int\ndtraced_self_procdesc(')
b = library.index('\n/* Serialize complete frames', a)
send_start = b + 1
send_end = library.index('\ntypedef struct {', send_start)
c = command.index('static int\ndtraced_connection_lost(')
d = command.index('\nstatic void *\nlisten_dtraced(', c)
(out / 'consumer-reconnect.inc').write_text(
    library[a:b] + '\n' + library[send_start:send_end] + '\n' +
    command[c:d])
subprocess.run(['cc', '-pthread', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-include', str(root / 'contrib/hypertrace/tests/consumer-birth-mock.h'), '-I' + str(out),
    '-I' + str(root / 'usr.sbin/dtraced'), '-I' + str(root / 'sys'),
    str(Path(__file__).with_suffix('.c')), '-o', str(out / 'consumer-reconnect')],
    check=True)
subprocess.run([str(out / 'consumer-reconnect')], check=True, timeout=20)
