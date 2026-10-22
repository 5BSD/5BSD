#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Test identified ACK failure and exact replay on a replacement stream."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'cddl/contrib/opensolaris/cmd/dtrace/dtrace.c').read_text()
start = source.index('static int reconnect_dtraced(dtd_arg_t *, int *, int *);')
helper = source.index('static void\nexecution_identity_set(', start)
ack = source.index('static void\nack_identified_delivery(', helper)
end = source.index('/* A reconnect may replay the exact ingress', start)
(out / 'consumer-ack-reconnect.inc').write_text(
    source[start:source.index('\n', start) + 1] + source[ack:end])
subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    '-I' + str(root / 'usr.sbin/dtraced'), '-I' + str(root / 'sys'),
    str(Path(__file__).with_suffix('.c')),
    '-o', str(out / 'consumer-ack-reconnect')], check=True)
subprocess.run([str(out / 'consumer-ack-reconnect')], check=True, timeout=20)
