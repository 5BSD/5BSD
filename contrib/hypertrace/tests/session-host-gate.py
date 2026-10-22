#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production fresh-session host gate with ioctl fault injection."""
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/hypertrace.c').read_text()
parts = []
for name in ('hypertrace_session_retired', 'ht_session_gate_query', 'ht_session_host_gate_state',
             'hypertrace_session_host_stopped', 'hypertrace_session_host_released',
             'hypertrace_session_host_stop'):
    match = re.search(r'(?:static )?int\n' + name + r'\(', source)
    if match is None:
        raise SystemExit('Missing function: ' + name)
    parts.append(source[match.start():source.index('\n}', match.start()) + 2])
(out / 'session-host-gate.inc').write_text('\n'.join(parts))
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
               '-fsanitize=address,undefined', '-I' + str(out),
               '-I' + str(root / 'sys'),
               str(Path(__file__).with_suffix('.c')),
               '-o', str(out / 'session-host-gate')], check=True)
subprocess.run([str(out / 'session-host-gate')], check=True, timeout=30)
