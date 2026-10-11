#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Drive a disposable PF parity guest's serial console (expect/send).

Usage: console.py SOCKET [--log FILE] STEP...
where STEP is one of
  expect:REGEX        wait (up to --timeout seconds) for REGEX in new output
  send:TEXT           send TEXT followed by a newline
  sendfile:PATH       send the file's bytes (input not logged)
  sleep:SECONDS
The script fails with exit status 1 if an expectation times out.
Only sockets below /usr/obj/5BSD-pf-parity/ are accepted.
"""
import argparse
from pathlib import Path
import re
import socket
import sys
import time

p = argparse.ArgumentParser(description=__doc__,
                            formatter_class=argparse.RawDescriptionHelpFormatter)
p.add_argument('socket', type=Path)
p.add_argument('--timeout', type=float, default=120)
p.add_argument('--log', type=Path)
p.add_argument('steps', nargs='+')
a = p.parse_args()
path = a.socket.resolve()
if not str(path).startswith('/usr/obj/5BSD-pf-parity/'):
    p.error('only PF parity test sockets are accepted')
log = a.log.open('ab') if a.log else None
buf = ''
with socket.socket(socket.AF_UNIX) as conn:
    conn.settimeout(0.2)
    conn.connect(str(path))

    def pump():
        global buf
        try:
            data = conn.recv(65536)
        except TimeoutError:
            return
        if not data:
            raise SystemExit('console closed')
        if log:
            log.write(data)
            log.flush()
        text = data.decode(errors='replace')
        sys.stdout.write(text)
        sys.stdout.flush()
        buf += text

    for step in a.steps:
        kind, _, arg = step.partition(':')
        if kind == 'expect':
            rx = re.compile(arg, re.M)
            until = time.monotonic() + a.timeout
            while not rx.search(buf):
                if time.monotonic() > until:
                    print('\nCONSOLE_TIMEOUT waiting for %r' % arg, file=sys.stderr)
                    raise SystemExit(1)
                pump()
            m = rx.search(buf)
            buf = buf[m.end():]
        elif kind == 'send':
            conn.sendall((arg + '\n').encode())
        elif kind == 'sendraw':
            conn.sendall(arg.encode().decode('unicode_escape').encode())
        elif kind == 'sendfile':
            conn.sendall(Path(arg).read_bytes())
        elif kind == 'sleep':
            until = time.monotonic() + float(arg)
            while time.monotonic() < until:
                pump()
        else:
            p.error('unknown step ' + step)
    # drain briefly
    until = time.monotonic() + 0.5
    while time.monotonic() < until:
        pump()
