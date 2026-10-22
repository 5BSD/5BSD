#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production bhyve RX/TX packet-ID shape gate."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/pci_virtio_net.c').read_text()
start = source.index('static bool\npci_vtnet_packet_id_valid(')
end = source.index('\n}', start) + 2
(out / 'packet-v2-bhyve.inc').write_text(source[start:end] + '\n')
binary = out / 'packet-v2-bhyve'
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(root / 'sys'),
    '-I' + str(out), str(Path(__file__).with_suffix('.c')),
    '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
