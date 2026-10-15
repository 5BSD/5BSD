#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Send one QMP command to a disposable PF test guest."""
import argparse
import json
from pathlib import Path
import socket

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('socket', type=Path)
p.add_argument('command')
p.add_argument('arguments', nargs='?', default='{}')
a = p.parse_args()
path = a.socket.resolve()
if not str(path).startswith('/usr/obj/5BSD-pf-parity/'):
    p.error('only PF parity test sockets are accepted')
with socket.socket(socket.AF_UNIX) as conn:
    conn.settimeout(10)
    conn.connect(str(path))
    stream = conn.makefile('rwb', buffering=0)
    print(stream.readline().decode().strip())
    for i, (command, arguments) in enumerate([
        ('qmp_capabilities', {}), (a.command, json.loads(a.arguments))]):
        stream.write((json.dumps({'execute': command, 'arguments': arguments,
                                 'id': i}) + '\n').encode())
        while True:
            result = json.loads(stream.readline())
            if result.get('id') == i:
                print(json.dumps(result))
                if 'error' in result:
                    raise SystemExit(1)
                break
