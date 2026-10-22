#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production TAP enqueue/freeze cut with concurrent senders."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/net/if_tuntap.c').read_text()
parts = []
for signature in ('static int\ntap_transmit(', 'static int\ntap_v2_rx_freeze(',
                  'static int\ntap_v2_rx_queued('):
    start = source.index(signature)
    end = source.index('\n}', start) + 2
    parts.append(source[start:end])
(out / 'packet-v2-freeze.inc').write_text('\n\n'.join(parts) + '\n')
binary = out / 'packet-v2-freeze'
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
    '-pthread', '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.c')), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
