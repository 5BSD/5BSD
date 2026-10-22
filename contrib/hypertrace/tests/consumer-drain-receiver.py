#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the actual dtrace consumer drain receiver over a socketpair."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'cddl/contrib/opensolaris/cmd/dtrace/dtrace.c').read_text()
start = source.index('static int\nconsumer_drain_gate_held(')
end = source.index('\n/* The receiver cannot join', start)
(out / 'consumer-drain-receiver.inc').write_text(source[start:end])
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-UNDEBUG', '-pthread',
    '-fsanitize=address,undefined', '-I' + str(out),
    '-I' + str(root / 'usr.sbin/dtraced'),
    str(Path(__file__).with_suffix('.c')),
    '-o', str(out / 'consumer-drain-receiver-test')], check=True)
subprocess.run([str(out / 'consumer-drain-receiver-test')],
    check=True, timeout=30)
