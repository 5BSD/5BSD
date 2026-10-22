#!/usr/bin/env python3.12
"""Exercise the production V2 checkpoint TX-ring cut."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/pci_virtio_net.c').read_text()
start = source.index('static int\npci_vtnet_v2_tx_quiescent(')
end = source.index('\n}', start) + 2
(out / 'packet-v2-checkpoint.inc').write_text(source[start:end] + '\n')
backend = (root / 'usr.sbin/bhyve/net_backends.c').read_text()
start = backend.index('static int\ntap_checkpoint_rx_quiescent(')
end = backend.index('\n}', start) + 2
first = backend[start:end]
start = backend.index('static int\ntap_checkpoint_rx_freeze(')
end = backend.index('\n}', start) + 2
(out / 'packet-v2-backend-checkpoint.inc').write_text(
    first + '\n' + backend[start:end] + '\n')
first = backend.index('int\nnetbe_tagging_v2_supported(')
last = backend.index('\n}', backend.index('int\nnetbe_tagging_enable_v2(', first)) + 2
(out / 'packet-v2-backend-capability.inc').write_text(
    backend[first:last] + '\n')
binary = out / 'packet-v2-checkpoint'
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    str(Path(__file__).with_suffix('.c')), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
