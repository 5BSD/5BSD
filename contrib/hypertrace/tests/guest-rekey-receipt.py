#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the daemon's exact fenced receipt query against a fake device."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/dtraced/dtraced_dttransport.cc').read_text()
start = source.index('bool\nquery_guest_rekey_receipt(')
end = source.index('\nbool\nrecover_guest_rekey(', start)
(out / 'guest-rekey-receipt.inc').write_text(source[start:end])
subprocess.run(['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    '-I' + str(root / 'sys/dev/dttransport'), '-I' + str(root / 'sys'),
    str(Path(__file__).with_suffix('.cc')),
    '-o', str(out / 'guest-rekey-receipt-test')], check=True)
subprocess.run([str(out / 'guest-rekey-receipt-test')], check=True, timeout=30)
