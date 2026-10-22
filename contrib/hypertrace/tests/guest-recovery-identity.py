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
source = (root / 'usr.sbin/dtraced/dtraced_state.cc').read_text()
start = source.index('static bool\nvalidate_guest_recovery_identity(')
end = source.index('\nbool\nstate::setup_threads(', start)
(out / 'guest-recovery-identity.inc').write_text(source[start:end])
io_source = (root / 'usr.sbin/dtraced/dtraced_io.h').read_text()
deadline_start = io_source.index('static inline int64_t\ndtraced_io_deadline_from(')
deadline_end = io_source.index('/* Finish a pending nonblocking connect',
    deadline_start)
(out / 'guest-deadline.inc').write_text(
    io_source[deadline_start:deadline_end])
subprocess.run(['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    '-I' + str(root / 'sys/dev/dttransport'), '-I' + str(root / 'sys'),
    str(Path(__file__).with_suffix('.cc')),
    '-o', str(out / 'guest-recovery-identity-test')], check=True)
subprocess.run([str(out / 'guest-recovery-identity-test')], check=True,
    timeout=30)
