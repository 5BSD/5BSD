#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the actual collector stop receiver with controlled worker state."""
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'cddl/contrib/opensolaris/cmd/dtrace/dtrace.c').read_text()
a = source.index('static int\nconsumer_drain_gate_held(')
b = source.index('\n}', a) + 2
c = source.index('static int\nconsumer_stop_lock(')
d = source.index('\ntypedef struct dtrace_workarg', c)
stop_source = source[c:d]
start = stop_source.index('/* Acquire before collector tracing work')
end = stop_source.index('static int\nconsumer_stop_quiesce(', start)
stop_source = stop_source[:start] + stop_source[end:]
(out / 'consumer-stop-receiver.inc').write_text(source[a:b] + '\n' + stop_source)
e = source.index('\nstatic int\nprocess_new_pgp(', d)
(out / 'consumer-stop-worker.inc').write_text(source[d:e])
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-UNDEBUG', '-pthread',
    '-fsanitize=address,undefined', '-I' + str(out),
    '-I' + str(root / 'usr.sbin/dtraced'),
    str(Path(__file__).with_suffix('.c')),
    '-o', str(out / 'consumer-stop-receiver-test')], check=True)
subprocess.run([str(out / 'consumer-stop-receiver-test')], check=True, timeout=30)
