#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Consumer re-registration ordering stress for dtraced.

Usage: registration-order-stress.py BINARY OUTPUT [PARALLEL [CYCLES]]

BINARY is the daemon-main test executable (the actual dtraced objects with
the daemon-main.cc shim: HT_ROOT redirect, attestation emulation; no device,
installed daemon or VM is used). Each cycle starts a private daemon, registers
a HyperTrace consumer (HPI program registration), ingests one guest ELF so the
consumer receives it, drops the consumer without acknowledging execution, and
registers the same consumer session again. The re-registration releases the
replay of that upload to the new socket.

Oracle (dtrace(1) dtrace_send_message semantics): after sending the
registration, the client reads exactly one status byte. The first byte after
the registration must be that status (0x01), followed by the replayed frame
whose header begins with msg_type ELF (also 0x01). A frame written before
the status is detected as a first u64 msg_type of 1 with no preceding status
(bytes 01 00 ...), which a real consumer would misread as an ACK.

The race only appears with scheduling pressure, so cycles run PARALLEL-wide.
Before the fix in dtraced_job.cc (registration status sent under the client's
output lock) this reproduced in 13 of 210 cycles; see COVERAGE-daemon.5BSD.md.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

binary, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
parallel = int(sys.argv[3]) if len(sys.argv) > 3 else 6
cycles = int(sys.argv[4]) if len(sys.argv) > 4 else 15
assert binary.is_relative_to('/usr/obj') and out.is_relative_to('/usr/obj')
out.mkdir(parents=True, exist_ok=True)
HEADER = 520


def recv_exact(s, n):
    b = bytearray()
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError(len(b))
        b.extend(c)
    return bytes(b)


def connect(root):
    for _ in range(500):
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(5)
        try:
            s.connect(root + '/sub.sock')
            break
        except (ConnectionRefusedError, FileNotFoundError):
            s.close()
            time.sleep(0.02)
    recv_exact(s, 160)
    return s


def hello(kind, subs, ident, session=b''):
    return (struct.pack('<IIQ', kind, 67, subs) + ident.encode().ljust(128, b'\0') +
            session.ljust(16, b'\0'))


def frame(s, h, body=b''):
    s.sendall(struct.pack('<Q', len(h) + len(body)) + h + body)


def started(pid):
    # initialize() has returned once the daemon holds its four kqueues.
    for _ in range(500):
        out = subprocess.run(['procstat', '-f', str(pid)], capture_output=True,
                             text=True).stdout
        if [l.split()[3] for l in out.splitlines()[1:]
                if len(l.split()) > 3].count('k') >= 4:
            return
        time.sleep(0.02)


def cycle():
    with tempfile.TemporaryDirectory(prefix='htd-', dir='/tmp') as root:
        env = dict(os.environ, HT_ROOT=root, HT_ATTEST='7:9:guest-a',
                   LLVM_PROFILE_FILE=os.environ.get('LLVM_PROFILE_FILE', '/dev/null'))
        p = subprocess.Popen([str(binary), '-d', '-D', root + '/state', '-t', '2'],
                             env=env, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        try:
            for _ in range(500):
                if os.path.exists(root + '/sub.sock'):
                    break
                time.sleep(0.02)
            started(p.pid)
            ident = 'dtrace-%d-%s' % (os.getpid(), os.urandom(16).hex())

            def register():
                c = connect(root)
                c.sendall(hello(1, 3, ident, b'\xc2'))
                h = bytearray(HEADER)
                struct.pack_into('<QQ', h, 0, 20, 32)
                frame(c, bytes(h), hashlib.sha256(b'p').digest())
                return c

            c = register()
            if recv_exact(c, 1) != b'\1':
                return 'setup'
            g = connect(root)
            g.sendall(hello(2, 1, 'guest-a', b'\x42'))
            r, w = os.pipe()
            socket.send_fds(g, [b'\xa5'], [r])
            os.close(r)
            os.close(w)
            time.sleep(0.2)
            name, elf = b'guest-a', b'\x7fELF' + bytes(40)
            body = struct.pack('<IHHQQ', 0x32565448, 2, 7, 9, len(name)) + name + elf
            h = bytearray(HEADER)
            struct.pack_into('<QQQ', h, 0, 1, len(body), 601)
            h[24:40] = b'\xa1'.ljust(16, b'\0')
            h[40:56] = b'\xb1'.ljust(16, b'\0')
            h[80:87] = b'inbound'
            frame(g, bytes(h), body)
            if recv_exact(g, 1) != b'\1':
                return 'setup'
            hdr = recv_exact(c, HEADER)
            recv_exact(c, struct.unpack_from('<Q', hdr, 8)[0])
            c.close()
            time.sleep(0.4)
            c2 = register()
            c2.settimeout(3)
            got = b''
            try:
                while len(got) < 2:
                    chunk = c2.recv(4096)
                    if not chunk:
                        break
                    got += chunk
            except OSError:
                pass
            c2.close()
            g.close()
            if got[:2] == b'\1\1':
                return 'status-first'
            if got[:2] == b'\1\0':
                return 'frame-first'
            return 'other:' + got[:4].hex()
        finally:
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()


tally, lock = {}, threading.Lock()


def worker():
    for _ in range(cycles):
        try:
            outcome = cycle()
        except Exception as exc:
            outcome = 'error:' + type(exc).__name__
        with lock:
            tally[outcome] = tally.get(outcome, 0) + 1


threads = [threading.Thread(target=worker) for _ in range(parallel)]
for t in threads:
    t.start()
for t in threads:
    t.join()
# Setup losses under load are not ordering evidence; any frame-first fails.
ok = tally.get('frame-first', 0) == 0 and tally.get('status-first', 0) > 0
(out / 'results.json').write_text(json.dumps({'tally': tally, 'passed': ok}, indent=2) + '\n')
print('registration-order-stress:', json.dumps(tally), 'PASS' if ok else 'FAIL')
raise SystemExit(0 if ok else 1)
