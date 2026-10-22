#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production guest VirtIO-net packet-ID selection helper."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/dev/virtio/network/if_vtnet.c').read_text()
start = source.index('static int\nvtnet_rx_packet_id_v2(')
end = source.index('\n}', start) + 2
(out / 'vtnet-packet-id-rx-v2.inc').write_text(source[start:end] + '\n')
start = source.index('static int\nvtnet_tx_packet_id(')
end = source.index('\nstatic int\nvtnet_tx_packet_id_v2(', start)
(out / 'vtnet-packet-id.inc').write_text(source[start:end] + '\n')
start = end + 1
end = source.index('\nstatic int\nvtnet_txq_encap(', start)
(out / 'vtnet-packet-id-v2.inc').write_text(source[start:end] + '\n')
mbufid_source = (root / 'sys/kern/subr_mbufid.c').read_text()
generate_start = mbufid_source.index('void\nmbufid_generate(')
valid_start = mbufid_source.index('int\nmbufid_isvalid(')
(out / 'mbufid-generate.inc').write_text(
    mbufid_source[generate_start:valid_start])
(out / 'mbufid-valid.inc').write_text(mbufid_source[valid_start:])
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    '-I' + str(root / 'sys'),
    str(Path(__file__).with_suffix('.c')),
    '-o', str(out / 'vtnet-packet-id-test')], check=True)
subprocess.run([str(out / 'vtnet-packet-id-test')], check=True, timeout=30)
