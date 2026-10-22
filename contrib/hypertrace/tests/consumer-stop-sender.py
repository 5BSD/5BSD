#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the daemon's exact fresh-session stop reply validation without a live daemon."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/dtraced/dtraced_connection.cc').read_text()
start = source.index('bool\nclient_fd::request_consumer_stop(')
end = source.index('\n}', start) + 2
(out / 'consumer-stop-sender.inc').write_text(source[start:end] + '\n')
subprocess.run(['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
    '-UNDEBUG', '-pthread', '-fsanitize=address,undefined',
    '-I' + str(out), '-I' + str(root / 'usr.sbin/dtraced'),
    str(Path(__file__).with_suffix('.cc')),
    '-o', str(out / 'consumer-stop-sender-test')], check=True)
subprocess.run([str(out / 'consumer-stop-sender-test')],
    check=True, timeout=30)
