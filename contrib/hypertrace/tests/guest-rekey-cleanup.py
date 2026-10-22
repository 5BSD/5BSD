#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check bounded session quiesce and cleanup of owned tracing children."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/dtraced/dtraced_dttransport.cc').read_text()
start = source.index('template <class Mutex>\nstatic bool\ndtt_stop_lock(')
end = source.index('\nstatic bool\nsend_next_recovery_query(', start)
(out / 'guest-rekey-cleanup.inc').write_text(source[start:end])
subprocess.run(['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.cc')),
    '-o', str(out / 'guest-rekey-cleanup-test')], check=True)
subprocess.run([str(out / 'guest-rekey-cleanup-test')], check=True,
    timeout=30)
