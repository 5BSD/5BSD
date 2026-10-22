#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check the daemon preserves a migrated inbound journal's durable key."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/dtraced/dtraced_process.cc').read_text()
start = source.index('durable_delivery\nguest_delivery_record(')
end = source.index('\n}', start) + 2
(out / 'guest-delivery-key.inc').write_text(source[start:end])
subprocess.run(['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.cc')), '-lcrypto',
    '-o', str(out / 'guest-delivery-key-test')], check=True)
subprocess.run([str(out / 'guest-delivery-key-test')], check=True, timeout=30)
