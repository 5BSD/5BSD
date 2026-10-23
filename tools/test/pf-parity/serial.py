#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exchange console input with a disposable PF parity guest."""
import argparse
from pathlib import Path
import socket
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('socket', type=Path)
p.add_argument('--send', default='', help='text to send with a trailing newline')
p.add_argument('--send-file', type=Path, help='send exact bytes; do not log input')
p.add_argument('--wait', type=float, default=2)
a = p.parse_args()
path = a.socket.resolve()
if not str(path).startswith('/usr/obj/5BSD-pf-parity/'):
    p.error('only PF parity test sockets are accepted')
if a.wait < 0 or a.wait > 30:
    p.error('wait must be between 0 and 30 seconds')
with socket.socket(socket.AF_UNIX) as conn:
    conn.settimeout(0.5)
    conn.connect(str(path))
    if a.send_file:
        conn.sendall(a.send_file.read_bytes())
    elif a.send:
        conn.sendall((a.send + '\n').encode())
    until = time.monotonic() + a.wait
    while time.monotonic() < until:
        try:
            data = conn.recv(65536)
            if not data:
                break
            print(data.decode(errors='replace'), end='', flush=True)
        except TimeoutError:
            pass
