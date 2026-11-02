#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Process-level scenarios for the actual dtraced main() built with daemon-main.cc.

Usage: daemon-main.py BINARY OUTPUT

Every run uses a private /tmp/htd-* root (HT_ROOT); the shim refuses /var and
/dev paths, so no installed daemon, socket, pid file or device is touched.
Oracles are exact exit statuses and diagnostics, the pid file content while
running, the control socket's server hello, statistics replies decoded from
the fixed wire layout, and removal of the socket and pid file on shutdown.
"""
from pathlib import Path
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

binary, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
# DAEMON_MAIN_ONLY=name[,name]: run only these scenarios (development)
ONLY = [n for n in os.environ.get('DAEMON_MAIN_ONLY', '').split(',') if n]
unsigned_binary = Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else None
out.mkdir(parents=True, exist_ok=True)
VERSION, HELLO, HEADER = 67, 160, 520
KIND_CONSUMER, KIND_FORWARDER, KIND_DTRACED = 1, 2, 3
MSG_STATS = 15
results = []


def run(name, args, env_extra=None, expect_status=None, expect_err=None,
        expect_out=None, root=None, timeout=20, program=None, expect_log=None):
    if ONLY and name not in ONLY:
        return None
    with tempfile.TemporaryDirectory(prefix='htd-', dir='/tmp') as tmp:
        root = root or tmp
        env = dict(os.environ, HT_ROOT=root, **(env_extra or {}))
        args = [a.replace('@ROOT@', root) for a in args]
        p = subprocess.run([str(program or binary), *args], env=env,
                           capture_output=True, text=True, timeout=timeout)
        ok = p.returncode == expect_status
        if expect_err is not None:
            ok = ok and expect_err in p.stderr
        if expect_out is not None:
            # LOG lines precede the version text on stdout
            ok = ok and p.stdout.endswith(expect_out) and \
                p.stdout.count('dtraced: version') == 1
        if expect_log is not None:
            ok = ok and expect_log in p.stdout
        ok = ok and not os.path.exists(os.path.join(root, 'sub.sock'))
        results.append({'case': name, 'status': p.returncode, 'passed': ok,
                        'stderr': p.stderr[-600:], 'stdout': p.stdout[-200:]})


def hello(kind, subs, ident, session=b''):
    return (struct.pack('<IIQ', kind, VERSION, subs) +
            ident.encode().ljust(128, b'\0') + session.ljust(16, b'\0'))


def recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError(len(data))
        data.extend(chunk)
    return bytes(data)


def connect(root):
    # The socket is bound before the consumer thread starts listening.
    end = time.monotonic() + 10
    while True:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect(os.path.join(root, 'sub.sock'))
            break
        except ConnectionRefusedError:
            s.close()
            if time.monotonic() > end:
                raise
            time.sleep(0.02)
    server = recv_exact(s, HELLO)
    assert struct.unpack_from('<IIQ', server) == (KIND_DTRACED, VERSION, 0), server[:16]
    assert server[16:] == bytes(144)
    return s


def stats_request(s, names=()):
    header = bytearray(HEADER)
    struct.pack_into('<Q', header, 0, MSG_STATS)
    struct.pack_into('<Q', header, 304, len(names))
    body = b''.join(struct.pack('<Q', len(n) + 1) + n.encode() + b'\0'
                    for n in names)
    frame = bytes(header) + body
    s.sendall(struct.pack('<Q', len(frame)) + frame)


def wait_for(path, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if os.path.exists(path):
            return True
        time.sleep(0.02)
    return False



def wait_started(pid, timeout=15):
    """True once initialize() has returned: the main thread's outbound
    watcher adds a fourth kqueue to the consumer and the two directory
    watchers' kqueues (observed with procstat -f; no daemon change)."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        p = subprocess.run(['procstat', '-f', str(pid)], capture_output=True,
                           text=True)
        kinds = [line.split()[3] for line in p.stdout.splitlines()[1:]
                 if len(line.split()) > 3]
        if kinds.count('k') >= 4:
            return True
        if p.returncode != 0:
            return False
        time.sleep(0.02)
    return False


def live(name, args, body, env_extra=None, stop=signal.SIGTERM, expect_status=0,
         ignored=()):
    if ONLY and name not in ONLY:
        return None
    """Start the daemon, run body(root, proc) against it, stop it."""
    with tempfile.TemporaryDirectory(prefix='htd-', dir='/tmp') as root:
        env = dict(os.environ, HT_ROOT=root, **{k: v.replace('@ROOT@', root)
                   for k, v in (env_extra or {}).items()})
        args = [a.replace('@ROOT@', root) for a in args]

        def dispositions():
            # Exact control of what the daemon inherits across exec.
            for sig in (signal.SIGINT, signal.SIGTERM):
                signal.signal(sig, signal.SIG_IGN if sig in ignored else
                              signal.SIG_DFL)
        # Logs go to files: an undrained pipe would block a busy daemon.
        out_log = open(os.path.join(root, 'stdout.log'), 'w+')
        err_log = open(os.path.join(root, 'stderr.log'), 'w+')
        proc = subprocess.Popen([str(binary), *args], env=env,
                                stdout=out_log, stderr=err_log,
                                text=True, preexec_fn=dispositions)
        detail = {}
        ok = False
        try:
            ok = wait_for(os.path.join(root, 'sub.sock')) and \
                wait_started(proc.pid)
            pidfile = Path(root) / 'dtraced.pid'
            ok = ok and wait_for(str(pidfile)) and \
                pidfile.read_text().strip() == str(proc.pid)
            if ok:
                try:
                    detail = body(root, proc) or {}
                    ok = detail.pop('ok', True)
                except Exception as exc:	# a protocol step failed
                    import traceback
                    detail = {'exception': traceback.format_exc()[-1200:]}
                    ok = False
        finally:
            if proc.poll() is None:
                proc.send_signal(stop)
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            out_log.seek(0)
            err_log.seek(0)
            stdout, stderr = out_log.read(), err_log.read()
            out_log.close()
            err_log.close()
        ok = ok and proc.returncode == expect_status and \
            not os.path.exists(os.path.join(root, 'sub.sock')) and \
            not os.path.exists(os.path.join(root, 'dtraced.pid'))
        results.append({'case': name, 'status': proc.returncode, 'passed': ok,
                        'detail': detail, 'stderr': stderr[-800:]})


# ---- argument and startup failures ----
run('help', ['-h'], expect_status=255, expect_err='Usage:',
    expect_log='running in overlord mode')
run('version', ['-v'], expect_status=0,
    expect_out='dtraced: version 0.4.0-BETA')
run('unknown-option', ['-x'], expect_status=255,
    expect_out='dtraced: version 0.4.0-BETA')
run('relative-directory', ['-D', 'relative'], expect_status=64,
    expect_err='Invalid directory')
run('long-directory', ['-D', '/' + 'a' * 1100], expect_status=64,
    expect_err='Invalid directory')
for bad in ('0', 'abc', '1025', '-1'):
    run('workers-' + bad, ['-t', bad], expect_status=64,
        expect_err='Invalid worker count')
run('sysctl-failure', ['-d'], {'HT_VM_GUEST': 'fail'}, expect_status=71,
    expect_err='kern.vm_guest')
run('already-running', ['-d', '-D', '@ROOT@/state'], {'HT_PIDFILE': 'exists'},
    expect_status=71, expect_err='already running as pid 4242')
run('pidfile-unopenable', ['-d', '-D', '@ROOT@/state'], {'HT_PIDFILE': 'fail'},
    expect_status=71, expect_err='Could not open')
run('daemonize-failure', ['-D', '@ROOT@/state'], {'HT_DAEMON': 'fail'},
    expect_status=71, expect_err='Failed to daemonize')
run('pidfile-write-failure', ['-d', '-D', '@ROOT@/state'], {'HT_PIDWRITE': 'fail'},
    expect_status=71, expect_err='Failed to write PID')
run('state-directory-uncreatable', ['-d', '-D', '@ROOT@/missing/state'],
    expect_status=71, expect_err='Failed to mkdir')
run('default-directory-refused', ['-d'], expect_status=71,
    expect_err='Failed to open /var/ddtrace')
run('keys-half-configured', ['-d', '-D', '@ROOT@/state', '-K', '@ROOT@/k.pem'],
    expect_status=1)
run('keys-unreadable', ['-d', '-D', '@ROOT@/state', '-K', '@ROOT@/k.pem',
                        '-P', '@ROOT@/p.pem'], expect_status=1,
    expect_err='failed to load HyperTrace host keys')
run('minion-without-transport', ['-d', '-D', '@ROOT@/state', '-m'],
    expect_status=1, expect_err='/dev/dttransport')
run('bhyve-guest-defaults-to-minion', ['-d', '-D', '@ROOT@/state'],
    {'HT_VM_GUEST': 'bhyve'}, expect_status=1, expect_err='/dev/dttransport',
    expect_log='running in minion mode')
run('overlord-on-guest-warns', ['-d', '-D', '@ROOT@/state', '-O', '-q'],
    {'HT_VM_GUEST': 'bhyve', 'HT_BIND': 'fail'}, expect_status=1,
    expect_err='overlord mode')
run('minion-on-metal-warns', ['-d', '-D', '@ROOT@/state', '-m'],
    expect_status=1, expect_err='minion')
# -q before -m suppresses the warning (errors are still reported)
run('quiet-suppresses-warnings', ['-q', '-d', '-D', '@ROOT@/state', '-m'],
    expect_status=1, expect_err='/dev/dttransport')
if results and results[-1]['case'] == 'quiet-suppresses-warnings':
    results[-1]['passed'] = results[-1]['passed'] and 'WARNING' not in results[-1]['stderr']
run('control-socket-bind-failure', ['-d', '-D', '@ROOT@/state'],
    {'HT_BIND': 'fail'}, expect_status=1, expect_err='failed to bind')
# The control directory is the socket's only access control.
for mode in (0o750, 0o701):
    with tempfile.TemporaryDirectory(prefix='htd-', dir='/tmp') as loose:
        os.chmod(loose, mode)
        run('control-directory-mode-%o' % mode, ['-d', '-D', '@ROOT@/state'],
            expect_status=71, expect_err='must be owned by uid',
            root=loose)

# Regression: with an unsigned char ABI (arm64, riscv64) the former `char ch`
# never compared equal to getopt's -1, so every invocation fell into the
# default case and exited with the version string instead of starting.
if unsigned_binary is not None:
    run('unsigned-char-option-loop', ['-d', '-D', '@ROOT@/state', '-t', '1'],
        {'HT_BIND': 'fail'}, expect_status=1, expect_err='failed to bind',
        program=unsigned_binary)
    run('unsigned-char-version', ['-v'], expect_status=0,
        expect_out='dtraced: version 0.4.0-BETA', program=unsigned_binary)

# ---- running daemon ----
def statistics(root, proc):
    detail = {}
    # A non-root consumer is refused (EPERM -> NAK and close).
    s = connect(root)
    s.sendall(hello(KIND_CONSUMER, 1, 'dtracedctl-%d' % os.getpid()))
    stats_request(s)
    detail['nonroot_reply'] = s.recv(1).hex()
    s.close()
    return {'ok': detail['nonroot_reply'] in ('00', ''), **detail}


live('run-and-terminate', ['-d', '-D', '@ROOT@/state', '-t', '2', '-Z'],
     statistics)


def forwarder(root, ident, session=b'\x42', subs=2):
    f = connect(root)
    f.sendall(hello(KIND_FORWARDER, subs, ident, session))
    r, w = os.pipe()
    socket.send_fds(f, [b'\xa5'], [r])
    os.close(r)
    os.close(w)
    return f


def stats(root, names=()):
    s = connect(root)
    s.sendall(hello(KIND_CONSUMER, 1, 'dtracedctl-%d' % os.getpid()))
    stats_request(s, names)
    ack = recv_exact(s, 1)
    counts = struct.unpack('<4Q', recv_exact(s, 32)) if ack == b'\1' else None
    s.close()
    return counts


def root_statistics(root, proc):
    # An attested forwarder channel is counted by a (simulated) root
    # consumer; a forwarder whose attestation names another VM is refused.
    f = forwarder(root, 'guest-a')
    bad = forwarder(root, 'guest-b')
    refused = bad.recv(1) == b''
    bad.close()
    time.sleep(0.2)
    counts = stats(root)
    named = stats(root, ['guest-a', 'absent'])
    absent = stats(root, ['absent'])
    f.close()
    time.sleep(0.2)
    after = stats(root)
    return {'ok': refused and counts == (1, 0, 0, 0) and named == (1, 0, 0, 0)
            and absent == (0, 0, 0, 0) and after == (0, 0, 0, 0),
            'counts': counts, 'named': named, 'absent': absent, 'after': after,
            'refused': refused}


def channel_layouts(root, proc):
    # Regression (protocol tightening): a forwarder may not combine READDATA
    # with CLEANUP; the cleanup ACK would be read as a READDATA frame header.
    # bhyve's layouts (ht_connect) stay admitted.
    refused = {}
    for name, subs in (('readdata+cleanup', 0x1 | 0x8),
                       ('readdata+cleanup+admission', 0x1 | 0x8 | 0x20)):
        try:
            # the daemon closes after the hello, before the attestation
            f = forwarder(root, 'guest-a', subs=subs)
        except BrokenPipeError:
            refused[name] = True
            continue
        f.settimeout(5)
        try:
            refused[name] = f.recv(1) == b''
        except ConnectionResetError:
            refused[name] = True
        except (OSError, socket.timeout):
            refused[name] = False
        f.close()
    with open(os.path.join(root, 'stderr.log')) as log:
        refused['logged'] = 'refused client hello (kind 2, subscriptions 0x9)' in log.read()
    admitted = {}
    for name, subs in (('rx', 0x2 | 0x4 | 0x8 | 0x20 | 0x40), ('wx', 0x1 | 0x20),
                       ('report', 0x1)):
        f = forwarder(root, 'guest-a', subs=subs)
        f.settimeout(5)
        try:
            if subs & 0x20:
                admitted[name] = recv_exact(f, 1) == b'\1'
            else:
                time.sleep(0.3)
                admitted[name] = stats(root) == (1, 0, 0, 0)
        except (OSError, socket.timeout, EOFError):
            admitted[name] = False
        f.close()
        time.sleep(0.2)
    return {'ok': all(refused.values()) and all(admitted.values()),
            'refused': refused, 'admitted': admitted}


live('forwarder-channel-layouts', ['-d', '-D', '@ROOT@/state', '-t', '1'],
     channel_layouts, {'HT_PEER_ROOT': '1', 'HT_ATTEST': '7:9:guest-a'},
     stop=signal.SIGINT)


live('statistics-as-root', ['-d', '-D', '@ROOT@/state', '-t', '1'],
     root_statistics, {'HT_PEER_ROOT': '1', 'HT_ATTEST': '7:9:guest-a'},
     stop=signal.SIGINT)


def unattested(root, proc):
    f = connect(root)
    f.sendall(hello(KIND_FORWARDER, 2, 'guest-a', b'\x42'))
    refused = f.recv(1) == b''
    f.close()
    return {'ok': refused and stats(root) == (0, 0, 0, 0)}


live('forwarder-without-attestation', ['-d', '-D', '@ROOT@/state'],
     unattested, {'HT_PEER_ROOT': '1'})


def bad_hello(root, proc):
    s = connect(root)
    s.sendall(hello(9, 1, 'nobody'))
    closed = s.recv(1) == b''
    s.close()
    s = connect(root)
    s.sendall(b'\0' * 10)
    s.close()
    return {'ok': closed and proc.poll() is None}


live('invalid-client-hello', ['-d', '-D', '@ROOT@/state'], bad_hello)

def settled(root, proc):
    # A served request plus a short pause: setup_threads() has returned, so
    # the stop signal tests shutdown rather than an interrupted startup
    # (which deliberately exits 1).
    s = connect(root)
    s.sendall(hello(KIND_CONSUMER, 1, 'dtracedctl-%d' % os.getpid()))
    stats_request(s)
    s.recv(1)
    s.close()
    time.sleep(0.5)
    return {}


# Regression: SIGINT/SIGTERM inherited as ignored (e.g. a background job of a
# non-interactive shell) were discarded by the kernel, so sigwait() never
# returned and the daemon could not be stopped.
for sig in (signal.SIGINT, signal.SIGTERM):
    live('stop-with-inherited-ignored-' + signal.Signals(sig).name,
         ['-d', '-D', '@ROOT@/state', '-t', '1'],
         settled, 
         stop=sig, ignored=(signal.SIGINT, signal.SIGTERM))


# ---- independent journal encoder (HTD3/HTD4 delivery records) ----
import hashlib


def delivery_record(version, session, delivery, vmid, epoch, program, source,
                    uid, pid, scope, digest=b''):
    body = bytearray(79 if version == 3 else 111)
    body[0:4] = b'HTD3' if version == 3 else b'HTD4'
    body[4:20] = session.ljust(16, b'\0')
    struct.pack_into('<QHQ', body, 20, delivery, vmid, epoch)
    body[38:54] = program.ljust(16, b'\0')
    body[54:70] = source.ljust(16, b'\0')
    struct.pack_into('<II', body, 70, uid, pid)
    body[78] = scope
    if version == 4:
        body[79:111] = digest
    return bytes(body) + hashlib.sha256(body).digest()


def delivery_name(session, delivery, phase):
    return '.delivery.%s.%016x.%s' % (session.ljust(16, b'\0').hex(), delivery, phase)


def spool_name(program, source):
    return 'elf.%s.%s' % (program.ljust(16, b'\0').hex(), source.ljust(16, b'\0').hex())


def put(directory, name, data, mode=0o600):
    path = Path(directory) / name
    path.write_bytes(data)
    os.chmod(path, mode)


# ---- revocation flow and hostile peers against the running daemon ----
MSG_KILL, MSG_INFO, MSG_KILL_APPLIED, MSG_SESSION_STOP = 2, 4, 9, 24


def kill_header(kind, pid, vmid, epoch, source):
    h = bytearray(HEADER)
    struct.pack_into('<Q', h, 0, kind)
    struct.pack_into('<IHxxQ', h, 272, pid, vmid, epoch)
    h[288:304] = source.ljust(16, b'\0')
    return bytes(h)


def frame(sock, header, body=b''):
    sock.sendall(struct.pack('<Q', len(header) + len(body)) + header + body)


def decode_kill(wire):
    kind = struct.unpack_from('<Q', wire, 0)[0]
    pid, vmid, epoch = struct.unpack_from('<IHxxQ', wire, 272)
    return kind, pid, vmid, epoch, bytes(wire[288:304])


def consumer(root, subs=1, ident=None):
    c = connect(root)
    c.sendall(hello(KIND_CONSUMER, subs, ident or 'dtracedctl-%d' % os.getpid()))
    return c


def expect_closed(sock):
    sock.settimeout(5)
    try:
        return sock.recv(1) == b''
    except (ConnectionResetError, socket.timeout):
        return False


def revocation(root, proc):
    detail = {}
    src1, src2 = b'\x55', b'\x56'
    f = forwarder(root, 'guest-a', subs=5)		# READDATA | KILL
    time.sleep(0.2)
    c = consumer(root)
    frame(c, kill_header(MSG_KILL, 4242, 7, 9, src1))
    detail['kill_ack'] = recv_exact(c, 1).hex()
    k = decode_kill(recv_exact(f, HEADER))
    detail['delivered'] = k == (MSG_KILL, 4242, 7, 9, src1.ljust(16, b'\0'))
    frame(f, kill_header(MSG_KILL_APPLIED, 4242, 7, 9, src1))
    detail['applied_ack'] = recv_exact(f, 1).hex()
    # A KILL_APPLIED for a lifetime this forwarder is not attested for.
    frame(f, kill_header(MSG_KILL_APPLIED, 4242, 8, 9, src1))
    detail['foreign_applied'] = recv_exact(f, 1).hex()
    f.close()
    # Revocation while no forwarder is connected is durable and replayed.
    frame(c, kill_header(MSG_KILL, 4343, 7, 9, src2))
    detail['offline_kill_ack'] = recv_exact(c, 1).hex()
    # Malformed revocation headers are rejected by the frame decoder, which
    # retires the connection; a KILL frame with a body is refused (NAK).
    closed = []
    for bad in ((1, 7, 9, src1), (4444, 0, 9, src1), (4444, 7, 0, src1),
                (4444, 7, 9, b'')):
        x = consumer(root)
        frame(x, kill_header(MSG_KILL, *bad))
        closed.append(expect_closed(x))
    detail['invalid_kills_closed'] = all(closed)
    frame(c, kill_header(MSG_KILL, 4545, 7, 9, src1), b'body')
    detail['kill_with_body'] = recv_exact(c, 1).hex()
    time.sleep(0.2)
    # Every durable revocation for this VM lifetime is replayed to a new
    # forwarder (KILL is idempotent and must survive guest restarts), the
    # applied one included; nothing else is sent.
    g = forwarder(root, 'guest-a', subs=5)
    replayed = sorted(decode_kill(recv_exact(g, HEADER)) for _ in range(2))
    detail['replayed'] = replayed == [
        (MSG_KILL, 4242, 7, 9, src1.ljust(16, b'\0')),
        (MSG_KILL, 4343, 7, 9, src2.ljust(16, b'\0'))]
    g.settimeout(0.5)
    try:
        extra = g.recv(1)
    except socket.timeout:
        extra = None
    detail['nothing_else'] = extra is None
    # The ordered replay manifest names every revocation for this lifetime.
    m = forwarder(root, 'guest-a', subs=2 | 4 | 32 | 64)	# ELFWRITE|KILL|ACK|MANIFEST
    detail['manifest_ack'] = recv_exact(m, 1).hex()
    count = struct.unpack('<I', recv_exact(m, 4))[0]
    entries = [struct.unpack('<iHxxQ16s', recv_exact(m, 32)) for _ in range(count)]
    detail['manifest'] = [(p, v, e, s[:1].hex()) for p, v, e, s in entries]
    g.close()
    m.close()
    c.close()
    ok = (detail['kill_ack'] == '01' and detail['delivered'] and
          detail['applied_ack'] == '01' and detail['foreign_applied'] == '00' and
          detail['offline_kill_ack'] == '01' and detail['invalid_kills_closed'] and
          detail['kill_with_body'] == '00'
          and detail['replayed'] and detail['nothing_else'] and
          detail['manifest_ack'] == '01' and
          detail['manifest'] == [(4242, 7, 9, '55'), (4343, 7, 9, '56')])
    return {'ok': ok and proc.poll() is None, **detail}


live('revocation-delivery-and-replay', ['-d', '-D', '@ROOT@/state', '-t', '2'],
     revocation, {'HT_ATTEST': '7:9:guest-a'})


def hostile(root, proc):
    detail = {}
    # frame shorter than a header, longer than the limit, undecodable header
    c = consumer(root); c.sendall(struct.pack('<Q', 10) + b'x' * 10)
    detail['short_frame'] = expect_closed(c)
    c = consumer(root); c.sendall(struct.pack('<Q', 64 * 1024 * 1024 + 1))
    detail['huge_frame'] = expect_closed(c)
    c = consumer(root); frame(c, b'\xee' + bytes(HEADER - 1))
    detail['bad_header'] = expect_closed(c)
    # A half-closed peer with a truncated body is retired on EOF.
    c = consumer(root)
    c.sendall(struct.pack('<Q', HEADER + 100) + kill_header(MSG_KILL, 5, 7, 9, b'1') + b'x' * 40)
    c.shutdown(socket.SHUT_WR)
    detail['truncated_closed'] = expect_closed(c)
    # A body that never completes is abandoned at the 10 s frame deadline:
    # client_fd::recv() shuts the socket before read_data() tries its NAK,
    # so the peer observes only EOF (documented in COVERAGE-daemon).
    c = consumer(root)
    c.sendall(struct.pack('<Q', HEADER + 100) + kill_header(MSG_KILL, 5, 7, 9, b'1') + b'x' * 40)
    c.settimeout(20)
    started = time.monotonic()
    detail['stalled_body'] = c.recv(1).hex()
    detail['stalled_after_s'] = round(time.monotonic() - started, 1)
    detail['stalled_closed'] = expect_closed(c)
    # session stop with the wrong body size
    c = consumer(root)
    h = bytearray(HEADER); struct.pack_into('<Q', h, 0, MSG_SESSION_STOP)
    frame(c, bytes(h), b'\0' * 3)
    detail['session_stop_size'] = expect_closed(c)
    # a well-formed message the consumer may not send: NAK, stays open
    c = consumer(root)
    h = bytearray(HEADER); struct.pack_into('<Q', h, 0, MSG_INFO)
    frame(c, bytes(h))
    detail['info_from_consumer'] = c.recv(1).hex()
    stats_request(c)
    detail['still_served'] = c.recv(1).hex()
    c.close()
    # refused admissions
    r = connect(root)
    r.sendall(hello(4, 0x100, 'hypertrace-release-recovery'))
    detail['release_recovery_refused'] = expect_closed(r)
    e = connect(root)
    e.sendall(hello(KIND_CONSUMER, 2, 'dtrace-1-%032x' % 1))	# birth names pid 1
    detail['bad_birth_refused'] = expect_closed(e)
    sr = connect(root)
    sr.sendall(hello(KIND_FORWARDER, 0x80 | 0x20, 'guest-a', b'\x43'))
    rr, ww = os.pipe()
    socket.send_fds(sr, [b'\xa5'], [rr])
    os.close(rr); os.close(ww)
    detail['source_release_without_epoch_device'] = expect_closed(sr)
    # INFO subscription lists the connected clients
    keep = forwarder(root, 'guest-a', subs=5)
    time.sleep(0.1)
    i = consumer(root, subs=16, ident='info-client')
    info = recv_exact(i, HEADER)
    kind, = struct.unpack_from('<Q', info, 0)
    count, = struct.unpack_from('<Q', info, 328)
    names = []
    for _ in range(count):
        entry = recv_exact(i, 132)
        names.append((struct.unpack_from('<I', entry, 0)[0],
                      entry[4:].split(b'\0')[0].decode()))
    detail['info'] = sorted(names)
    i.close(); keep.close()
    ok = (all(detail[k] for k in ('short_frame', 'huge_frame', 'bad_header',
          'truncated_closed', 'session_stop_size', 'release_recovery_refused',
          'bad_birth_refused', 'source_release_without_epoch_device')) and
          detail['stalled_body'] == '' and 9 <= detail['stalled_after_s'] <= 15 and
          detail['stalled_closed'] and
          detail['info_from_consumer'] == '00'
          and detail['still_served'] == '01' and kind == MSG_INFO and
          (KIND_FORWARDER, 'guest-a') in names and (KIND_CONSUMER, 'info-client') in names)
    return {'ok': ok and proc.poll() is None, **detail}


live('hostile-peers', ['-d', '-D', '@ROOT@/state', '-t', '2'], hostile,
     {'HT_ATTEST': '7:9:guest-a', 'HT_PEER_ROOT': '1'})


MSG_CLEANUP, MSG_CLEANUP_APPLIED = 3, 18


def cleanup_request(sock, names):
    h = bytearray(HEADER)
    struct.pack_into('<Q', h, 0, MSG_CLEANUP)
    struct.pack_into('<Q', h, 304, len(names))
    body = b''.join(struct.pack('<Q', len(n) + 1) + n.encode() + b'\0' for n in names)
    frame(sock, bytes(h), body)


def read_cleanup(sock):
    h = recv_exact(sock, HEADER)
    kind, = struct.unpack_from('<Q', h, 0)
    count, = struct.unpack_from('<Q', h, 304)
    vmid, = struct.unpack_from('<H', h, 312)
    epoch, token = struct.unpack_from('<QQ', h, 320)
    names = []
    for _ in range(count):
        n = struct.unpack('<Q', recv_exact(sock, 8))[0]
        names.append(recv_exact(sock, n)[:-1].decode())
    return kind, vmid, epoch, token, names


def cleanup_applied(sock, vmid, epoch, token):
    h = bytearray(HEADER)
    struct.pack_into('<Q', h, 0, MSG_CLEANUP_APPLIED)
    struct.pack_into('<H', h, 312, vmid)
    struct.pack_into('<QQ', h, 320, epoch, token)
    frame(sock, bytes(h))


def cleanup_flow(root, proc):
    d = {}
    # bhyve's layout: cleanups and their queue ACK on a CLEANUP channel,
    # CLEANUP_APPLIED reports on a READDATA channel
    f = forwarder(root, 'guest-a', subs=8)
    r = forwarder(root, 'guest-a', subs=1)
    time.sleep(0.2)
    c = consumer(root)
    cleanup_request(c, ['guest-a'])
    d['request_ack'] = recv_exact(c, 1).hex()
    kind, vmid, epoch, token, names = read_cleanup(f)
    d['delivered'] = (kind, vmid, epoch, names) == (MSG_CLEANUP, 7, 9, ['guest-a']) and token != 0
    f.sendall(struct.pack('<Q', token))			# queue ACK
    cleanup_applied(r, 7, 9, token)
    d['applied_ack'] = recv_exact(r, 1).hex()
    cleanup_applied(r, 7, 10, token)			# wrong lifetime
    d['foreign_applied'] = recv_exact(r, 1).hex()
    # A selector naming another VM reaches no forwarder.
    cleanup_request(c, ['other'])
    d['other_ack'] = recv_exact(c, 1).hex()
    f.settimeout(0.4)
    try:
        d['other_delivered'] = f.recv(1) != b''
    except socket.timeout:
        d['other_delivered'] = False
    f.settimeout(5)
    # Unacknowledged cleanup is replayed with the same token on reconnect.
    cleanup_request(c, [])
    d['all_ack'] = recv_exact(c, 1).hex()
    kind, vmid, epoch, pending, names = read_cleanup(f)
    d['all_delivered'] = (kind, names) == (MSG_CLEANUP, []) and pending not in (0, token)
    f.close()
    time.sleep(0.2)
    g = forwarder(root, 'guest-a', subs=8)
    kind, vmid, epoch, replayed, names = read_cleanup(g)
    d['replayed_same_token'] = replayed == pending and (vmid, epoch) == (7, 9)
    g.sendall(struct.pack('<Q', replayed))
    cleanup_applied(r, 7, 9, replayed)
    d['replay_applied_ack'] = recv_exact(r, 1).hex()
    g.close()
    time.sleep(0.2)
    h = forwarder(root, 'guest-a', subs=8)
    h.settimeout(0.5)
    try:
        d['nothing_after_applied'] = h.recv(1) == b''
    except socket.timeout:
        d['nothing_after_applied'] = True
    h.close()
    r.close()
    c.close()
    ok = (d['request_ack'] == '01' and d['delivered'] and d['applied_ack'] == '01'
          and d['foreign_applied'] == '00' and d['other_ack'] == '01' and
          not d['other_delivered'] and d['all_ack'] == '01' and d['all_delivered']
          and d['replayed_same_token'] and d['replay_applied_ack'] == '01' and
          d['nothing_after_applied'])
    return {'ok': ok and proc.poll() is None, **d}


live('cleanup-delivery-and-replay', ['-d', '-D', '@ROOT@/state', '-t', '2'],
     cleanup_flow, {'HT_ATTEST': '7:9:guest-a', 'HT_PEER_ROOT': '1'})


def nonroot_cleanup(root, proc):
    c = consumer(root)
    cleanup_request(c, [])
    return {'ok': recv_exact(c, 1) == b'\0'}


live('cleanup-requires-root', ['-d', '-D', '@ROOT@/state'], nonroot_cleanup)


def restores_deliveries(root, proc):
    # Accepted and installed host deliveries for this exact forwarder
    # identity (session, peer, VM lifetime) are restored on reconnect;
    # pending ones and other identities are not.
    out_dir = Path(root) / 'state' / 'outbound'
    me = os.getpid()
    rows = [(b'\x42', 91, 'a', me, 7, 9), (b'\x42', 92, 'i', me, 7, 9),
            (b'\x42', 93, 'p', me, 7, 9), (b'\x43', 94, 'a', me, 7, 9),
            (b'\x42', 95, 'a', me + 1, 7, 9), (b'\x42', 96, 'a', me, 7, 8)]
    for session, delivery, phase, pid, vmid, epoch in rows:
        put(out_dir, delivery_name(session, delivery, phase), delivery_record(
            3, session, delivery, vmid, epoch, bytes([delivery]), b'\x99', 0,
            pid, 0))
    f = forwarder(root, 'guest-a', session=b'\x42', subs=2)	# ELFWRITE
    time.sleep(0.3)
    counts = stats(root)
    f.close()
    return {'ok': counts == (1, 2, 0, 0), 'counts': counts}


live('forwarder-reconnect-restores-deliveries', ['-d', '-D', '@ROOT@/state', '-t', '2'],
     restores_deliveries, {'HT_ATTEST': '7:9:guest-a', 'HT_PEER_ROOT': '1'})


# ---- host outbound delivery lifecycle (consumer -> forwarder -> observer) ----
MSG_ELF, MSG_INSTALLED, MSG_UNINSTALLED = 1, 5, 6


def elf_header(length, source, location=b'outbound', program=b'', delivery=0):
    h = bytearray(HEADER)
    struct.pack_into('<QQQ', h, 0, MSG_ELF, length, delivery)
    h[24:40] = program.ljust(16, b'\0')
    h[40:56] = source.ljust(16, b'\0')
    h[80:80 + len(location)] = location
    return bytes(h)


def observation(kind, delivery, vmid, epoch, program, source, name):
    h = bytearray(HEADER)
    struct.pack_into('<Q', h, 0, kind)
    struct.pack_into('<QHxxxxxxQ', h, 336, delivery, vmid, epoch)
    h[360:376] = program
    h[376:392] = source
    h[392:392 + len(name)] = name.encode()
    return bytes(h)


MSG_STATUS, MSG_INGRESS_STATUS = 7, 8


def status_query(sock, kind, delivery, program, source, name='guest-a', vmid=7,
                 epoch=9):
    frame(sock, observation(kind, delivery, vmid, epoch, program, source, name))
    ack = recv_exact(sock, 1)
    if ack != b'\1':
        return None
    w = recv_exact(sock, 48)
    did, = struct.unpack_from('<Q', w, 0)
    return (did, w[8], w[9], w[10], w[16:48])


def delivery_lifecycle(root, proc):
    d = {}
    elf = b'\x7fELF' + bytes(range(60))
    writer = forwarder(root, 'guest-a', session=b'\x42', subs=2)		# ELFWRITE
    reader = forwarder(root, 'guest-a', session=b'\x42', subs=1 | 4)	# READDATA|KILL
    time.sleep(0.2)
    c = consumer(root)
    frame(c, elf_header(len(elf), b'\x5a'), elf)
    d['publish_ack'] = recv_exact(c, 1).hex()
    hdr = recv_exact(writer, HEADER)
    kind, length, delivery = struct.unpack_from('<QQQ', hdr, 0)
    program, source = hdr[24:40], hdr[40:56]
    body = recv_exact(writer, length)
    # bhyve's device takes a bare ELF (pci_vtdtr_elf_target()); a SHA-256
    # prefixed body is failed without an ACK, so the delivery never lands.
    d['frame'] = (kind == MSG_ELF and length == len(elf) and delivery != 0 and
                  body == elf and
                  source == b'\x5a'.ljust(16, b'\0') and program != bytes(16))
    pending_name = delivery_name(b'\x42', delivery, 'p')
    out_dir = Path(root) / 'state' / 'outbound'
    d['pending_before_ack'] = (out_dir / pending_name).exists()
    writer.sendall(struct.pack('<Q', delivery))		# guest queue ACK
    time.sleep(0.2)
    d['accepted'] = (out_dir / delivery_name(b'\x42', delivery, 'a')).exists()
    d['after_accept'] = stats(root)
    frame(reader, observation(MSG_INSTALLED, delivery, 7, 9, program, source, 'guest-a'))
    d['installed_ack'] = recv_exact(reader, 1).hex()
    d['after_install'] = stats(root)
    d['installed_on_disk'] = (out_dir / delivery_name(b'\x42', delivery, 'i')).exists()
    # The guest's recovery query sees the installed phase and, with the
    # delivering channel still attached, a replay grant with the digest.
    st = status_query(reader, MSG_STATUS, delivery, program, source)
    d['status_installed'] = st is not None and st[0] == delivery and \
        st[1] == ord('i') and st[2] == 0 and st[3] == 1 and \
        st[4] == hashlib.sha256(elf).digest()
    st = status_query(reader, MSG_STATUS, delivery + 7, program, source)
    d['status_absent'] = st is not None and st[1] == 0 and st[3] == 0
    d['status_foreign'] = status_query(reader, MSG_STATUS, delivery, program,
                                       source, epoch=8) is None
    # observations that do not match the attested VM or token are refused
    frame(reader, observation(MSG_INSTALLED, delivery, 7, 8, program, source, 'guest-a'))
    d['foreign_install'] = recv_exact(reader, 1).hex()
    frame(reader, observation(MSG_INSTALLED, delivery + 1, 7, 9, program, source, 'guest-a'))
    d['unknown_install'] = recv_exact(reader, 1).hex()
    frame(reader, observation(MSG_INSTALLED, delivery, 7, 9, program, source, 'guest-b'))
    d['wrong_name'] = recv_exact(reader, 1).hex()
    # the guest reports the program gone: terminal journal, channel retired
    frame(reader, observation(MSG_UNINSTALLED, delivery, 7, 9, program, source, 'guest-a'))
    d['uninstalled_ack'] = recv_exact(reader, 1).hex()
    d['after_uninstall'] = stats(root)
    d['terminal_on_disk'] = (out_dir / delivery_name(b'\x42', delivery, 't')).exists()
    frame(reader, observation(MSG_UNINSTALLED, delivery, 7, 9, program, source, 'guest-a'))
    d['repeat_uninstall'] = recv_exact(reader, 1).hex()
    # a second publication is revoked before installation
    frame(c, elf_header(len(elf), b'\x5b'), elf)
    d['second_ack'] = recv_exact(c, 1).hex()
    hdr2 = recv_exact(writer, HEADER)
    delivery2 = struct.unpack_from('<Q', hdr2, 16)[0]
    recv_exact(writer, struct.unpack_from('<Q', hdr2, 8)[0])
    writer.sendall(struct.pack('<Q', delivery2))
    time.sleep(0.2)
    d['before_kill'] = stats(root)
    frame(c, kill_header(MSG_KILL, 777, 7, 9, b'\x5b'))
    d['kill_ack'] = recv_exact(c, 1).hex()
    d['kill_to_reader'] = decode_kill(recv_exact(reader, HEADER))[1] == 777
    time.sleep(0.2)
    d['after_kill'] = stats(root)		# an accepted delivery is dropped
    # revoked while the guest has not yet acknowledged the frame
    frame(c, elf_header(len(elf), b'\x5c'), elf)
    d['third_ack'] = recv_exact(c, 1).hex()
    hdr3 = recv_exact(writer, HEADER)
    delivery3 = struct.unpack_from('<Q', hdr3, 16)[0]
    recv_exact(writer, struct.unpack_from('<Q', hdr3, 8)[0])
    frame(c, kill_header(MSG_KILL, 778, 7, 9, b'\x5c'))
    d['kill2_ack'] = recv_exact(c, 1).hex()
    decode_kill(recv_exact(reader, HEADER))
    d['revoked_unacked'] = stats(root)
    writer.sendall(struct.pack('<Q', delivery3))
    time.sleep(0.2)
    for sock in (writer, reader, c):
        sock.close()
    ok = (d['publish_ack'] == '01' and d['frame'] and d['pending_before_ack'] and
          d['accepted'] and d['after_accept'] == (2, 1, 0, 0) and
          d['installed_ack'] == '01' and d['after_install'] == (2, 1, 1, 0) and
          d['status_installed'] and d['status_absent'] and d['status_foreign'] and
          d['installed_on_disk'] and d['foreign_install'] == '00' and
          d['unknown_install'] == '00' and d['wrong_name'] == '00' and
          d['uninstalled_ack'] == '01' and d['after_uninstall'] == (2, 0, 0, 0) and
          d['terminal_on_disk'] and d['repeat_uninstall'] == '01' and
          d['second_ack'] == '01' and d['kill_ack'] == '01' and d['kill_to_reader']
          and d['before_kill'] == (2, 1, 0, 0) and d['after_kill'] == (2, 0, 0, 0)
          and d['third_ack'] == '01' and d['kill2_ack'] == '01' and
          d['revoked_unacked'] == (2, 1, 0, 1))
    return {'ok': ok and proc.poll() is None, **d}


live('outbound-delivery-lifecycle', ['-d', '-D', '@ROOT@/state', '-t', '2'],
     delivery_lifecycle, {'HT_ATTEST': '7:9:guest-a', 'HT_PEER_ROOT': '1'})


# ---- host ingest: guest ELF -> host journal -> registered host consumer ----
MSG_CONSUMER_PROGRAM = 20
ENVELOPE_MAGIC = 0x32565448


def guest_elf_frame(sock, delivery, program, source, name, elf, vmid=7, epoch=9):
    body = struct.pack('<IHHQQ', ENVELOPE_MAGIC, 2, vmid, epoch, len(name)) + \
        name.encode() + elf
    frame(sock, elf_header(len(body), source, b'inbound', program, delivery), body)
    return body


def host_ingest(root, proc):
    d = {}
    elf = b'\x7fELF' + bytes(range(80))
    birth = os.urandom(16).hex()
    c = connect(root)
    c.sendall(hello(KIND_CONSUMER, 1 | 2, 'dtrace-%d-%s' % (os.getpid(), birth),
                    b'\xc1'))			# READDATA|ELFWRITE host consumer
    digest = hashlib.sha256(b'compiled program').digest()
    h = bytearray(HEADER)
    struct.pack_into('<QQ', h, 0, MSG_CONSUMER_PROGRAM, 32)
    frame(c, bytes(h), digest)
    d['program_ack'] = recv_exact(c, 1).hex()
    g = forwarder(root, 'guest-a', session=b'\x42', subs=1)	# READDATA
    time.sleep(0.2)
    body = guest_elf_frame(g, 501, b'\x81', b'\x91', 'guest-a', elf)
    d['ingest_ack'] = recv_exact(g, 1).hex()
    # The registered consumer receives the accepted upload.
    hdr = recv_exact(c, HEADER)
    kind, length, delivery = struct.unpack_from('<QQQ', hdr, 0)
    vmid, = struct.unpack_from('<H', hdr, 64)
    epoch, = struct.unpack_from('<Q', hdr, 72)
    payload = recv_exact(c, length)
    # Host consumers receive the stored upload (envelope, VM name, ELF)
    # without a digest prefix; identity comes from the accepted journal.
    d['to_consumer'] = (kind == MSG_ELF and delivery == 501 and vmid == 7 and
                        epoch == 9 and hdr[24:40] == b'\x81'.ljust(16, b'\0') and
                        hdr[40:56] == b'\x91'.ljust(16, b'\0') and
                        length == len(body) and payload == body)
    in_dir = Path(root) / 'state' / 'inbound'
    d['accepted_journal'] = any(p.name.startswith('.delivery.') and p.name.endswith('.a')
                                for p in in_dir.iterdir())
    st = status_query(g, MSG_INGRESS_STATUS, 501, b'\x81'.ljust(16, b'\0'),
                      b'\x91'.ljust(16, b'\0'))
    d['ingress_status'] = st is not None and st[1] == ord('a') and st[2] == 0 and \
        st[4] == hashlib.sha256(elf).digest()
    st = status_query(g, MSG_INGRESS_STATUS, 599, b'\x81'.ljust(16, b'\0'),
                      b'\x91'.ljust(16, b'\0'))
    d['ingress_absent'] = st is not None and st[1] == 0
    # The consumer reports that it processed the upload without deriving.
    ack = struct.pack('<Q16s16sHBxxxxxQ', 501, b'\x81', b'\x91', 7, 1, 9)
    c.sendall(ack)
    time.sleep(0.3)
    d['receipts'] = sorted(p.name[-1] for p in in_dir.iterdir()
                           if p.name.startswith('.consumer.'))
    # An exact retry of the accepted upload is idempotent; a different
    # payload for the same token is refused.
    guest_elf_frame(g, 501, b'\x81', b'\x91', 'guest-a', elf)
    d['retry_ack'] = recv_exact(g, 1).hex()
    guest_elf_frame(g, 501, b'\x81', b'\x91', 'guest-a', elf + b'!')
    d['conflict_ack'] = recv_exact(g, 1).hex()
    # Envelopes that do not match the attested VM are refused.
    guest_elf_frame(g, 502, b'\x82', b'\x92', 'guest-a', elf, vmid=8)
    d['wrong_vm'] = recv_exact(g, 1).hex()
    guest_elf_frame(g, 503, b'\x83', b'\x93', 'guest-b', elf)
    d['wrong_name'] = recv_exact(g, 1).hex()
    # A revoked source cannot be ingested.
    k = consumer(root)
    frame(k, kill_header(MSG_KILL, 900, 7, 9, b'\x94'))
    d['kill_ack'] = recv_exact(k, 1).hex()
    k.close()
    guest_elf_frame(g, 504, b'\x84', b'\x94', 'guest-a', elf)
    d['revoked_source'] = recv_exact(g, 1).hex()
    st = status_query(g, MSG_INGRESS_STATUS, 504, b'\x84'.ljust(16, b'\0'),
                      b'\x94'.ljust(16, b'\0'))
    d['revoked_status'] = st is not None and st[1] == 0 and st[2] == 1
    g.close()
    c.close()
    ok = (d['program_ack'] == '01' and d['ingest_ack'] == '01' and d['to_consumer']
          and d['accepted_journal'] and d['receipts'] == ['n'] and
          d['ingress_status'] and d['ingress_absent'] and d['revoked_status'] and
          d['retry_ack'] == '01' and d['conflict_ack'] == '00' and
          d['wrong_vm'] == '00' and d['wrong_name'] == '00' and
          d['kill_ack'] == '01' and d['revoked_source'] == '00')
    return {'ok': ok and proc.poll() is None, **d}


live('host-ingest-to-consumer', ['-d', '-D', '@ROOT@/state', '-t', '2'],
     host_ingest, {'HT_ATTEST': '7:9:guest-a'})


def base_program_routing(root, proc):
    # The dtrace -E contract (dtrace.c): the host consumer sends its unlinked
    # base program, bound to its source ID, to location "base"; dtraced copies
    # it to outbound for the guests and launches a host
    # `dtrace -q -Y <base>,host`, whose linked result returns to "inbound"
    # (also with the source ID). Only inbound programs - that host link
    # result or guest uploads, both linked - may reach registered host
    # consumers. Regressions: the base copy lost its source and was refused
    # by (and killed) the guest channel; the host link result was named like
    # a journaled guest upload and silently dropped.
    d = {}
    source = b'\x5a'
    base = b'\x7fELF' + b'BASE-unlinked-typecast' * 3
    linked = b'\x7fELF' + b'LINKED-host-nop' * 3
    guest_linked = b'\x7fELF' + b'LINKED-guest-nop' * 3
    writer = forwarder(root, 'guest-a', session=b'\x42', subs=2)	# ELFWRITE
    reader = forwarder(root, 'guest-a', session=b'\x42', subs=1)	# READDATA
    time.sleep(0.2)
    birth = os.urandom(16).hex()
    ident = 'dtrace-%d-%s' % (os.getpid(), birth)
    rx = connect(root)
    rx.sendall(hello(KIND_CONSUMER, 1 | 2, ident, b'\xc7'))
    h = bytearray(HEADER)
    struct.pack_into('<QQ', h, 0, MSG_CONSUMER_PROGRAM, 32)
    frame(rx, bytes(h), hashlib.sha256(b'program-base-routing').digest())
    d['registered'] = recv_exact(rx, 1).hex()
    wx = connect(root)
    wx.sendall(hello(KIND_CONSUMER, 1, ident))
    # a sourceless base cannot go to guests; the guest channel survives
    nosrc = b'\x7fELF' + b'BASE-without-source' * 2
    frame(wx, elf_header(len(nosrc), b'', b'base'), nosrc)
    d['nosource_ack'] = recv_exact(wx, 1).hex()
    frame(wx, elf_header(len(base), source, b'base'), base)
    d['base_ack'] = recv_exact(wx, 1).hex()
    # guests receive exactly the unlinked base (a bare ELF, as bhyve's device
    # requires), with its source lineage and a fresh program ID
    hdr = recv_exact(writer, HEADER)
    kind, length, delivery = struct.unpack_from('<QQQ', hdr, 0)
    body = recv_exact(writer, length)
    d['base_to_guest'] = (kind == MSG_ELF and delivery != 0 and
                          hdr[40:56] == source.ljust(16, b'\0') and
                          hdr[24:40] != bytes(16) and
                          length == len(base) and body == base)
    writer.sendall(struct.pack('<Q', delivery))
    # both bases launch the host link
    log = Path(root) / 'exec.log'
    end = time.monotonic() + 5
    while time.monotonic() < end and not (
            log.exists() and log.read_text().count(',host') == 2):
        time.sleep(0.05)
    launches = log.read_text().splitlines() if log.exists() else []
    d['host_launch'] = [l.replace(root, '@ROOT@') for l in launches]
    prefix = '/usr/sbin/dtrace /usr/sbin/dtrace -q -Y ' + root + '/state/base/elf.'
    d['launch_ok'] = (len(launches) == 2 and
                      all(l.startswith(prefix) and l.endswith(',host')
                          for l in launches))
    # the registered consumer receives nothing from a base program
    rx.settimeout(1.5)
    try:
        d['consumer_before_link'] = rx.recv(1).hex()
    except socket.timeout:
        d['consumer_before_link'] = 'none'
    rx.settimeout(10)
    # host -Y result: linked program to "inbound", with the source ID
    hy = connect(root)
    hy.sendall(hello(KIND_CONSUMER, 1, 'dtrace-host-link'))
    frame(hy, elf_header(len(linked), source, b'inbound'), linked)
    d['host_link_ack'] = recv_exact(hy, 1).hex()
    hdr = recv_exact(rx, HEADER)
    kind, length = struct.unpack_from('<QQ', hdr, 0)
    got = recv_exact(rx, length)
    d['host_linked_to_consumer'] = kind == MSG_ELF and got == linked
    # guest result: linked program uploaded by the guest
    body = guest_elf_frame(reader, 777, b'\x77', b'\x78', 'guest-a', guest_linked)
    d['guest_ack'] = recv_exact(reader, 1).hex()
    hdr = recv_exact(rx, HEADER)
    kind, length = struct.unpack_from('<QQ', hdr, 0)
    got = recv_exact(rx, length)
    d['guest_linked_to_consumer'] = kind == MSG_ELF and got == body and \
        got.endswith(guest_linked) and base not in got
    # the guest ELFWRITE channel was never retired
    d['writer_alive'] = stats(root)[0] == 2
    for sock in (writer, reader, rx, wx, hy):
        sock.close()
    ok = (d['registered'] == '01' and d['nosource_ack'] == '01' and
          d['base_ack'] == '01' and d['base_to_guest'] and
          d['launch_ok'] and d['consumer_before_link'] == 'none' and
          d['host_link_ack'] == '01' and d['host_linked_to_consumer'] and
          d['guest_ack'] == '01' and d['guest_linked_to_consumer'] and
          d['writer_alive'])
    return {'ok': ok and proc.poll() is None, **d}


live('base-program-routing', ['-d', '-D', '@ROOT@/state', '-t', '2'],
     base_program_routing, {'HT_ATTEST': '7:9:guest-a', 'HT_PEER_ROOT': '1',
                            'HT_EXEC_LOG': '@ROOT@/exec.log',
                            'HT_EXEC_FAKE': '1'})


def consumer_client():
    """consumer-elf-path.c on libdtrace's own transport, extracted as
    library-transport.py does."""
    root = Path(__file__).resolve().parents[3]
    lib = root / 'cddl/contrib/opensolaris/lib/libdtrace/common'
    source = (lib / 'dt_subr.c').read_text()
    a = source.index('static int\ndtraced_self_procdesc(')
    b = source.index('\nint\ndtrace_oformat_configure', a)
    c = source.index('int\ndtrace_program_source_id(', b)
    d = source.index('\nint\ndtrace_program_compiled_digest(', c)
    e = source.index('\nstatic int\ndtrace_send_elf_impl(', d)
    f = source.index('\nvoid\ndtrace_enable_hypertrace', e)
    (out / 'library-transport.inc').write_text(
        source[a:b] + source[c:d] + source[e:f])
    client = out / 'consumer-elf-path'
    subprocess.run(['cc', '-pthread', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unknown-pragmas', '-I' + str(out), '-I' + str(lib),
                    '-I' + str(root / 'usr.sbin/dtraced'),
                    '-I' + str(root / 'sys'), str(lib / 'dt_list.c'),
                    str(Path(__file__).with_name('consumer-elf-path.c')),
                    '-o', str(client), '-lcrypto'], check=True)
    return client


import threading


def compiled_elf(path, program):
    """A HyperTrace program as dtrace -E writes it: compiled with
    libdtrace (DTRACE_LIB, default the installed library) and serialized
    with dtrace_elf_create(), without the kernel (NODEV | NOSYS)."""
    import ctypes as C
    lib = C.CDLL(os.environ.get('DTRACE_LIB', '/lib/libdtrace.so.2'))
    lib.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]
    lib.dtrace_open.restype = C.c_void_p
    lib.dtrace_enable_hypertrace.argtypes = [C.c_void_p]
    lib.dtrace_program_strcompile.argtypes = [C.c_void_p, C.c_char_p, C.c_int,
                                              C.c_uint, C.c_int, C.c_void_p]
    lib.dtrace_program_strcompile.restype = C.c_void_p
    lib.dtrace_elf_create.argtypes = [C.c_void_p, C.c_void_p, C.c_int,
                                      C.c_int, C.c_char_p, C.c_char_p]
    lib.dtrace_close.argtypes = [C.c_void_p]
    error = C.c_int()
    hdl = lib.dtrace_open(3, 3, C.byref(error))	# VERSION 3; NODEV | NOSYS
    assert hdl, ('dtrace_open', error.value)
    try:
        lib.dtrace_enable_hypertrace(hdl)
        prog = lib.dtrace_program_strcompile(hdl, program, 4, 0x1004, 0, None)
        assert prog, ('compile', program)	# NAME; NOLIBS | ZDEFS
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            message = C.create_string_buffer(512)
            assert lib.dtrace_elf_create(hdl, prog, 1, fd, os.fsencode(path),
                                         message) == 0, message.value
        finally:
            os.close(fd)
    finally:
        lib.dtrace_close(hdl)
    return Path(path).read_bytes()


def consumer_elf_path(root, proc):
    # dtrace -E end to end through the event loop and workers, in dtrace(1)'s
    # order and with libdtrace's transport: the ELF-only receiver registers
    # (HPI2), the compiled base program reaches the guest, each linked guest
    # upload reaches the receiver, and the derived program it sends with
    # dtrace_send_elf_derived() before its ACK is published to the guest.
    # Regression: with the default single worker, the delivery to the
    # receiver held the worker until the ACK, the derived upload found none,
    # and dtrace -E timed out ("failed to dtrace_send_elf()").  Two queued
    # uploads model a glob target; the run uses the daemon's default -t.
    d = {'steps': []}
    base = out / 'consumer-elf-path.base'
    derived = out / 'consumer-elf-path.derived'
    base_elf = compiled_elf(base, b'syscall::getpid:entry { @htmark1 = count(); }')
    derived_elf = compiled_elf(derived, b'BEGIN { trace(1); }')
    writer = forwarder(root, 'guest-a', session=b'\x42', subs=2)	# ELFWRITE
    reader = forwarder(root, 'guest-a', session=b'\x42', subs=1)	# READDATA
    time.sleep(0.2)
    client = subprocess.Popen([str(CONSUMER_CLIENT),
                               os.path.join(root, 'sub.sock'), str(base),
                               str(derived), '2'], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True)

    def expect(*names):
        for name in names:
            line = client.stdout.readline().strip()
            d['steps'].append(line)
            if line != name + ' ok':
                return False
        return True

    def delivered(sock):
        hdr = recv_exact(sock, HEADER)
        kind, length, delivery = struct.unpack_from('<QQQ', hdr, 0)
        body = recv_exact(sock, length)
        sock.sendall(struct.pack('<Q', delivery))
        return hdr, (body if kind == MSG_ELF and delivery != 0 else None)

    try:
        writer.settimeout(15)
        d['registered'] = expect('rx', 'registered', 'wx', 'base')
        hdr, body = delivered(writer)
        d['base_to_guest'] = body == base_elf
        # bhyve acknowledges each delivery as it arrives
        received = []
        guest = threading.Thread(target=lambda: received.extend(
            delivered(writer)[1] for _ in range(2)), daemon=True)
        guest.start()
        d['guest_acks'] = []
        for delivery in (801, 802):
            guest_elf_frame(reader, delivery, bytes([delivery & 0xff]),
                            hdr[40:56], 'guest-a',
                            b'\x7fELF' + b'LINKED-guest-%d' % delivery * 8)
            d['guest_acks'].append(recv_exact(reader, 1).hex())
        d['derived_sent'] = expect('ingress', 'derived', 'acked') and \
            expect('ingress', 'derived', 'acked')
        guest.join(15)
        d['derived_to_guest'] = [body is not None and
                                 body.endswith(derived_elf)
                                 for body in received]
        time.sleep(0.3)
        d['stats'] = stats(root)
    finally:
        client.stdin.close()
        try:
            d['client_status'] = client.wait(timeout=10)
        except subprocess.TimeoutExpired:
            client.kill()
            d['client_status'] = client.wait()
        writer.close()
        reader.close()
    ok = (d['registered'] and d['base_to_guest'] and
          d['guest_acks'] == ['01', '01'] and d['derived_sent'] and
          d['derived_to_guest'] == [True, True] and d['stats'] is not None and
          d['stats'][1] == 3 and d['client_status'] == 0)
    return {'ok': ok and proc.poll() is None, **d}


if not ONLY or 'consumer-elf-path' in ONLY:
    CONSUMER_CLIENT = consumer_client()
    live('consumer-elf-path', ['-d', '-D', '@ROOT@/state'],
         consumer_elf_path, {'HT_ATTEST': '7:9:guest-a', 'HT_PEER_ROOT': '1',
                             'HT_EXEC_LOG': '@ROOT@/exec.log',
                             'HT_EXEC_FAKE': '1'})


def ingest_lost_ack(root, proc):
    # A host consumer that disconnects before acknowledging keeps its
    # receipt pending; the same consumer session reconnecting receives the
    # upload again and completes it.
    d = {}
    elf = b'\x7fELF' + bytes(range(40))
    birth = os.urandom(16).hex()
    ident = 'dtrace-%d-%s' % (os.getpid(), birth)

    def register():
        c = connect(root)
        c.sendall(hello(KIND_CONSUMER, 1 | 2, ident, b'\xc2'))
        h = bytearray(HEADER)
        struct.pack_into('<QQ', h, 0, MSG_CONSUMER_PROGRAM, 32)
        frame(c, bytes(h), hashlib.sha256(b'program-2').digest())
        return c, recv_exact(c, 1).hex()

    c, d['program_ack'] = register()
    g = forwarder(root, 'guest-a', session=b'\x42', subs=1)
    time.sleep(0.2)
    body = guest_elf_frame(g, 601, b'\xa1', b'\xb1', 'guest-a', elf)
    d['ingest_ack'] = recv_exact(g, 1).hex()
    hdr = recv_exact(c, HEADER)
    recv_exact(c, struct.unpack_from('<Q', hdr, 8)[0])
    c.close()						# lost ACK
    in_dir = Path(root) / 'state' / 'inbound'
    time.sleep(0.4)
    d['pending_after_loss'] = sorted(p.name[-1] for p in in_dir.iterdir()
                                     if p.name.startswith('.consumer.'))
    c2, d['reregister_ack'] = register()
    hdr = recv_exact(c2, HEADER)
    payload = recv_exact(c2, struct.unpack_from('<Q', hdr, 8)[0])
    d['replayed'] = struct.unpack_from('<Q', hdr, 16)[0] == 601 and payload == body
    c2.sendall(struct.pack('<Q16s16sHBxxxxxQ', 601, b'\xa1', b'\xb1', 7, 1, 9))
    time.sleep(0.3)
    d['final'] = sorted(p.name[-1] for p in in_dir.iterdir()
                        if p.name.startswith('.consumer.'))
    # A malformed ACK cannot certify processing.
    body2 = guest_elf_frame(g, 602, b'\xa2', b'\xb2', 'guest-a', elf)
    recv_exact(g, 1)
    hdr = recv_exact(c2, HEADER)
    recv_exact(c2, struct.unpack_from('<Q', hdr, 8)[0])
    c2.sendall(struct.pack('<Q16s16sHBxxxxxQ', 602, b'\xa2', b'\xb2', 7, 0, 9))
    time.sleep(0.3)
    d['after_bad_ack'] = sorted(p.name[-1] for p in in_dir.iterdir()
                                if p.name.startswith('.consumer.'))
    g.close()
    c2.close()
    ok = (d['program_ack'] == '01' and d['ingest_ack'] == '01' and
          d['pending_after_loss'] == ['p'] and d['reregister_ack'] == '01' and
          d['replayed'] and d['final'] == ['n'] and
          sorted(d['after_bad_ack']) == ['n', 'p'])
    return {'ok': ok and proc.poll() is None, **d}


live('host-ingest-lost-ack-replay', ['-d', '-D', '@ROOT@/state', '-t', '2'],
     ingest_lost_ack, {'HT_ATTEST': '7:9:guest-a'})


def consumer_delivery_isolation(root, proc):
    # A host consumer that never acknowledges a delivery holds the worker
    # sending to it until the 60 s ACK deadline; deliveries to another host
    # consumer must not queue behind it, also at the default -t 1 (the
    # one -t worker used to run them in turn).  Two uploads: one delivery worker stuck on the silent consumer
    # delays the live consumer's second delivery whatever the recipient
    # order, and a second worker must not take the silent consumer's next
    # delivery, which would wait on its stream as well.
    d = {'live': []}
    elf = b'\x7fELF' + bytes(range(40))

    def register(session):
        c = connect(root)
        c.sendall(hello(KIND_CONSUMER, 2, 'dtrace-%d-%s' %
                        (os.getpid(), os.urandom(16).hex()), session))
        h = bytearray(HEADER)
        struct.pack_into('<QQ', h, 0, MSG_CONSUMER_PROGRAM, 32)
        frame(c, bytes(h), hashlib.sha256(b'program-' + session).digest())
        return c, recv_exact(c, 1).hex()

    silent, d['silent_ack'] = register(b'\xc4')
    live_c, d['live_ack'] = register(b'\xc5')
    live_c.settimeout(10)
    g = forwarder(root, 'guest-a', session=b'\x42', subs=1)
    time.sleep(0.2)
    t0 = time.monotonic()
    try:
        for delivery in (901, 902):
            program, source = bytes([delivery & 0xff]), b'\xb4'
            guest_elf_frame(g, delivery, program, source, 'guest-a', elf)
            d.setdefault('ingest', []).append(recv_exact(g, 1).hex())
            hdr = recv_exact(live_c, HEADER)
            recv_exact(live_c, struct.unpack_from('<Q', hdr, 8)[0])
            got = struct.unpack_from('<Q', hdr, 16)[0]
            d['live'].append([got, round(time.monotonic() - t0, 2)])
            live_c.sendall(struct.pack('<Q16s16sHBxxxxxQ', got, program,
                                       source, 7, 1, 9))
    except (OSError, EOFError) as e:
        d['live'].append(repr(e))
    silent.settimeout(0.5)
    try:
        d['silent_received'] = len(silent.recv(HEADER)) > 0
    except OSError:
        d['silent_received'] = False
    g.close()
    live_c.close()
    silent.close()
    ok = (d['silent_ack'] == '01' and d['live_ack'] == '01' and
          d.get('ingest') == ['01', '01'] and len(d['live']) == 2 and
          all(isinstance(x, list) and x[1] < 5 for x in d['live']))
    return {'ok': ok and proc.poll() is None, **d}


live('consumer-delivery-isolation', ['-d', '-D', '@ROOT@/state'],
     consumer_delivery_isolation, {'HT_ATTEST': '7:9:guest-a'})


def registration_ordering(root, proc):
    # Regression: re-registering a consumer releases its replayed upload.
    # The one-byte registration status must reach the client before that
    # ELF frame (whose first byte equals an ACK). This checks the ordering
    # on an idle daemon; the race itself only appears under load and is
    # exercised by registration-order-stress.py.
    elf = b'\x7fELF' + bytes(range(40))
    ident = 'dtrace-%d-%s' % (os.getpid(), os.urandom(16).hex())

    def register():
        c = connect(root)
        c.sendall(hello(KIND_CONSUMER, 1 | 2, ident, b'\xc3'))
        h = bytearray(HEADER)
        struct.pack_into('<QQ', h, 0, MSG_CONSUMER_PROGRAM, 32)
        frame(c, bytes(h), hashlib.sha256(b'program-3').digest())
        return c

    c = register()
    first_ack = recv_exact(c, 1)
    g = forwarder(root, 'guest-a', session=b'\x42', subs=1)
    time.sleep(0.2)
    body = guest_elf_frame(g, 701, b'\xc1', b'\xd1', 'guest-a', elf)
    ingest = recv_exact(g, 1)
    hdr = recv_exact(c, HEADER)
    recv_exact(c, struct.unpack_from('<Q', hdr, 8)[0])
    c.close()
    time.sleep(0.4)
    c2 = register()
    status = recv_exact(c2, 1)
    hdr = recv_exact(c2, HEADER)
    payload = recv_exact(c2, struct.unpack_from('<Q', hdr, 8)[0])
    in_order = status == b'\1' and struct.unpack_from('<QQQ', hdr, 0)[0] == MSG_ELF \
        and struct.unpack_from('<Q', hdr, 16)[0] == 701 and payload == body
    c2.close()
    g.close()
    return {'ok': first_ack == b'\1' and ingest == b'\1' and in_order,
            'in_order': in_order}


live('registration-ack-precedes-replay', ['-d', '-D', '@ROOT@/state', '-t', '4'],
     registration_ordering, {'HT_ATTEST': '7:9:guest-a'})


# ---- admission and shutdown interleavings ----


def admission_storm(root, proc):
    # 64 concurrent statistics clients (simulated root) interleaved with
    # attested forwarders that connect and vanish: every client gets exactly
    # one well-formed reply and the daemon stays up.
    replies, errors = [], []
    lock = threading.Lock()

    def client(i):
        try:
            if i % 4 == 0:
                f = forwarder(root, 'guest-a', session=bytes([i % 250 + 1]), subs=5)
                time.sleep(0.01)
                f.close()
                return
            counts = stats(root)
            with lock:
                replies.append(counts)
        except Exception as exc:
            with lock:
                errors.append(repr(exc))
    threads = [threading.Thread(target=client, args=(i,)) for i in range(64)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    ok = (not errors and len(replies) == 48 and
          all(r is not None and r[1:] == (0, 0, 0) for r in replies) and
          proc.poll() is None and stats(root)[0] == 0)
    return {'ok': ok, 'errors': errors[:3], 'replies': len(replies)}


live('admission-storm', ['-d', '-D', '@ROOT@/state', '-t', '4'], admission_storm,
     {'HT_ATTEST': '7:9:guest-a', 'HT_PEER_ROOT': '1'})


def shutdown_under_load(root, proc):
    # Clients keep connecting, sending partial or complete requests and
    # disconnecting while the daemon is told to stop. Shutdown must complete
    # (live() requires exit 0 and removal of the socket and pid file).
    stop = threading.Event()

    def churn(i):
        while not stop.is_set():
            try:
                s = connect(root)
                s.sendall(hello(KIND_CONSUMER, 1, 'dtracedctl-%d' % os.getpid()))
                if i % 3 == 0:
                    stats_request(s)
                elif i % 3 == 1:
                    s.sendall(struct.pack('<Q', HEADER + 50) + bytes(10))
                s.close()
            except OSError:
                pass
    threads = [threading.Thread(target=churn, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    time.sleep(1.0)
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=25)
    except subprocess.TimeoutExpired:
        pass
    stop.set()
    for t in threads:
        t.join(10)
    return {'ok': proc.poll() == 0}


live('shutdown-under-load', ['-d', '-D', '@ROOT@/state', '-t', '4'],
     shutdown_under_load, {'HT_PEER_ROOT': '1'})


# ---- HyperTrace host release keys (-K/-P) ----
def make_keys(root):
    keys = Path(root) / 'keys'
    keys.mkdir(mode=0o700)
    def gen(name, algorithm='ed25519', extra=()):
        priv = keys / (name + '.pem')
        subprocess.run(['openssl', 'genpkey', '-algorithm', algorithm, *extra,
                        '-out', str(priv)], check=True, capture_output=True)
        os.chmod(priv, 0o600)
        pub = keys / (name + '.pub')
        subprocess.run(['openssl', 'pkey', '-in', str(priv), '-pubout', '-out',
                        str(pub), '-passin', 'pass:secret'], check=True,
                       capture_output=True)
        os.chmod(pub, 0o644)
        return priv, pub
    own, own_pub = gen('own')
    peer, peer_pub = gen('peer')
    rsa, rsa_pub = gen('rsa', 'rsa', ('-pkeyopt', 'rsa_keygen_bits:2048'))
    enc = keys / 'enc.pem'
    subprocess.run(['openssl', 'pkey', '-in', str(own), '-aes256', '-passout',
                    'pass:secret', '-out', str(enc)], check=True, capture_output=True)
    os.chmod(enc, 0o600)
    loose = keys / 'loose.pem'
    loose.write_bytes(own.read_bytes())
    os.chmod(loose, 0o644)
    return dict(own=own, own_pub=own_pub, peer_pub=peer_pub, rsa=rsa,
                rsa_pub=rsa_pub, enc=enc, loose=loose)


def key_case(name, private, peer, expect_status, expect_err=None, extra=()):
    with tempfile.TemporaryDirectory(prefix='htd-', dir='/tmp') as root:
        k = make_keys(root)
        args = ['-d', '-D', root + '/state', '-K',
                str(k[private]) if private in k else private,
                '-P', str(k[peer]) if peer in k else peer, *extra]
        env = dict(os.environ, HT_ROOT=root)
        if expect_status == 0:
            proc = subprocess.Popen([str(binary), *args], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True)
            started = wait_for(os.path.join(root, 'sub.sock')) and \
                wait_started(proc.pid)
            proc.send_signal(signal.SIGTERM)
            out_text, err_text = proc.communicate(timeout=20)
            status = proc.returncode
            ok = started and status == 0
        else:
            p = subprocess.run([str(binary), *args], env=env, capture_output=True,
                               text=True, timeout=20)
            status, err_text = p.returncode, p.stderr
            ok = status == expect_status
        if expect_err is not None:
            ok = ok and expect_err in err_text
        results.append({'case': name, 'status': status, 'passed': ok,
                        'stderr': err_text[-500:]})


key_case('keys-valid', 'own', 'peer_pub', 0)
key_case('keys-encrypted-private', 'enc', 'peer_pub', 1,
         'failed to load HyperTrace host keys: Protocol error')
key_case('keys-peer-is-self', 'own', 'own_pub', 1,
         'failed to load HyperTrace host keys: Protocol error')
key_case('keys-not-ed25519', 'rsa', 'peer_pub', 1,
         'failed to load HyperTrace host keys: Protocol error')
key_case('keys-peer-not-ed25519', 'own', 'rsa_pub', 1,
         'failed to load HyperTrace host keys: Protocol error')
key_case('keys-private-readable-by-others', 'loose', 'peer_pub', 1,
         'failed to load HyperTrace host keys: Operation not permitted')
key_case('keys-relative-path', 'keys/own.pem', 'peer_pub', 1,
         'failed to load HyperTrace host keys: Invalid argument')
key_case('keys-peer-missing', 'own', '/nonexistent/peer.pub', 1,
         'failed to load HyperTrace host keys: No such file or directory')
key_case('keys-peer-not-pem', 'own', '/dev/null', 1,
         'failed to load HyperTrace host keys: Operation not permitted')
key_case('keys-in-minion-mode', 'own', 'peer_pub', 1, None, ('-m',))


# ---- guest (minion) daemon with a scripted transport ----
def minion(name, identity, cleanup=None, after=None, cleanup_after=None,
           marker=False, busy=0, busy_errno=None, after_on=None, expect_status=0,
           expect_err=None,
           expect_records=None, live_run=True, expect_session=None,
           journals=None, expect_files=None, record_kinds=None, answer=False,
           body=None, max_stop_seconds=None):
    with tempfile.TemporaryDirectory(prefix='htd-', dir='/tmp') as root:
        state = Path(root) / 'state'
        state.mkdir(mode=0o700)
        (state / 'inbound').mkdir(mode=0o700)
        (state / 'outbound').mkdir(mode=0o700)
        if journals is not None:
            journals(state)
        if marker:
            fd = os.open(state / 'inbound' / '.child-ledger-v1',
                         os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        log = Path(root) / 'driver.log'
        env = dict(os.environ, HT_ROOT=root, HT_DTT_IDENTITY=identity,
                   HT_DTT_LOG=str(log), HT_DTT_BUSY=str(busy))
        for key, value in (('HT_DTT_CLEANUP', cleanup),
                           ('HT_DTT_IDENTITY_AFTER', after),
                           ('HT_DTT_CLEANUP_AFTER', cleanup_after),
                           ('HT_DTT_AFTER_ON', after_on),
                           ('HT_DTT_BUSY_ERRNO', busy_errno),
                           ('HT_DTT_ANSWER', '1' if answer else None)):
            if value is not None:
                env[key] = value
        proc = subprocess.Popen([str(binary), '-d', '-D', str(state), '-m', '-t', '1'],
                                env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        started = False
        detail = {}
        if live_run:
            started = wait_for(os.path.join(root, 'sub.sock')) and \
                wait_started(proc.pid)
            if body is not None and started:
                try:
                    detail = body(root, state) or {}
                except Exception:
                    import traceback
                    detail = {'ok': False, 'exception': traceback.format_exc()[-800:]}
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
        stop_started = time.monotonic()
        try:
            # A non-live start may legitimately wait out the daemon's 30 s
            # identity deadline before failing.
            stdout, stderr = proc.communicate(timeout=30 if live_run else 60)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
        stop_seconds = time.monotonic() - stop_started
        if max_stop_seconds is not None:
            detail['stop_seconds'] = round(stop_seconds, 2)
            if stop_seconds > max_stop_seconds:
                detail['ok'] = False
        records = log.read_text().split('\n')[:-1] if log.exists() else []
        ok = proc.returncode == expect_status and (started or not live_run)
        if expect_err is not None:
            ok = ok and expect_err in stderr
        if expect_records is not None:
            ok = ok and records == expect_records
        if record_kinds is not None:
            ok = ok and sorted(int(r.split()[0]) for r in records) == sorted(record_kinds)
        if expect_files is not None:
            for rel, present in expect_files.items():
                ok = ok and (state / rel).exists() == present
        if expect_session is not None:
            ok = ok and all((state / d / expect_session).is_dir()
                            for d in ('inbound', 'outbound', 'base'))
        if marker is False and expect_status == 0:
            ledger = state / 'inbound' / (expect_session or '.') / '.child-ledger-v1'
            ok = ok and ledger.is_file()
        if expect_status != 73:	# a re-exec leaves the socket to its successor
            ok = ok and not os.path.exists(os.path.join(root, 'sub.sock'))
        ok = ok and detail.pop('ok', True)
        results.append({'case': name, 'status': proc.returncode, 'passed': ok,
                        'records': records, 'detail': detail,
                        'stderr': stderr[-800:]})


# identity: flags,vmid,epoch,old_vmid,old_epoch; cleanup: flags,delivery,vmid,epoch,reserved
minion('minion-clean-start', '0,42,99,0,0', expect_records=[])
# Regression: the transport writer waited out its 10 s idle read deadline
# before noticing shutdown; a guest daemon now exits promptly on SIGTERM.
minion('minion-prompt-shutdown', '0,42,99,0,0', answer=True,
       body=lambda root, state: (time.sleep(0.5), {'ok': True})[1],
       max_stop_seconds=3)
minion('minion-identity-busy', '0,42,99,0,0', busy=3, expect_records=[])
minion('minion-identity-not-ready', '0,42,99,0,0', busy=2, busy_errno='ENXIO',
       expect_records=[])
# Regression (nested hosttest, gsv-record.md): a guest whose virtio-dtrace
# device never receives NODE_ID logged only "failed to open daemon
# directories: Operation timed out".  It must name the missing identity.
minion('minion-identity-never-assigned', '0,42,99,0,0', busy=1000000,
       busy_errno='ENXIO', expect_status=1, live_run=False,
       expect_err='no VM identity from /dev/dttransport within 30 s')
minion('minion-identity-never-assigned-step', '0,42,99,0,0', busy=1000000,
       expect_status=1, live_run=False,
       expect_err='failed to open daemon directories: guest startup identity: ')
minion('minion-invalid-identity', '0,0,99,0,0', expect_status=1,
       live_run=False, expect_err='failed to open daemon directories')
minion('minion-identity-unavailable', 'bogus', expect_status=1, live_run=False,
       expect_err='failed to open daemon directories')
minion('minion-rekey-empty-journals', '1,43,100,42,99', after='0,43,100,0,0',
       expect_records=[])
minion('minion-fresh-session', '4,43,100,42,99', cleanup='7,8,42,99,0',
       after='16,43,100,42,99', cleanup_after='0,0,0,0,0',
       expect_records=['27 8 43 100'], expect_session='.session.002b.0000000000000064')
minion('minion-fresh-ready-session', '8,43,100,42,99', cleanup='7,8,42,99,0',
       after='16,43,100,42,99', cleanup_after='0,0,0,0,0',
       expect_records=['27 8 43 100'], expect_session='.session.002b.0000000000000064')
minion('minion-fresh-active-without-session', '16,43,100,42,99', expect_status=1,
       live_run=False, expect_err='failed to open daemon directories')
minion('minion-fresh-stale-stop', '4,43,100,42,99', cleanup='7,8,41,99,0',
       expect_status=1, live_run=False, expect_err='failed to open daemon directories')
minion('minion-pending-cleanup-without-ledger', '0,42,99,0,0', cleanup='1,8,42,99,0',
       expect_status=1, live_run=False, expect_err='guest cleanup is not safely recovered')
minion('minion-pending-cleanup-applied', '0,42,99,0,0', cleanup='1,8,42,99,0',
       marker=True, expect_records=['24 8 42 99'])
minion('minion-applied-cleanup', '0,42,99,0,0', cleanup='3,8,42,99,0',
       marker=True, expect_records=[])
minion('minion-invalid-cleanup-state', '0,42,99,0,0', cleanup='1,8,42,99,1',
       expect_status=1, live_run=False, expect_err='guest cleanup is not safely recovered')
minion('minion-stopped-session-reexec', '0,42,99,0,0', cleanup='7,8,42,99,0',
       marker=True, after='4,43,100,42,99', after_on='any', expect_status=73,
       live_run=False, expect_records=['26 8 42 99'])
minion('minion-stopped-session-changed', '0,42,99,0,0', cleanup='7,8,42,99,0',
       marker=True, after='0,44,99,0,0', after_on='any', expect_status=1,
       live_run=False, expect_records=['26 8 42 99'],
       expect_err='guest cleanup is not safely recovered')


# Journal recovery at guest startup (scope 1 inbound, scope 2 outbound).
ELF_IN, ELF_OUT = b'\x7fELFin', b'\x7fELFout'
D_IN, D_OUT = hashlib.sha256(ELF_IN).digest(), hashlib.sha256(ELF_OUT).digest()


def guest_journals(vmid=42, epoch=99, scope_in=1):
    pid = 0 if scope_in == 1 else 100	# a host-ingest record names its peer

    def build(state):
        inb, outb = state / 'inbound', state / 'outbound'
        put(inb, delivery_name(b'\x11', 17, 'p'), delivery_record(
            4, b'\x11', 17, vmid, epoch, b'\x21', b'\x31', 0, pid, scope_in, D_IN))
        put(inb, delivery_name(b'\x12', 18, 't'), delivery_record(
            4, b'\x12', 18, vmid, epoch, b'\x22', b'\x32', 0, pid, scope_in, D_IN))
        put(inb, delivery_name(b'\x13', 19, 'x'), delivery_record(
            4, b'\x13', 19, vmid, epoch, b'\x23', b'\x33', 0, pid, scope_in, D_IN))
        put(inb, spool_name(b'\x21', b'\x31'), ELF_IN)
        put(outb, delivery_name(b'\x41', 51, 'p'), delivery_record(
            4, b'\x41', 51, vmid, epoch, b'\x51', b'\x61', 0, 100, 2, D_OUT))
        put(outb, spool_name(b'\x51', b'\x61'), ELF_OUT)
        put(outb, delivery_name(b'\x42', 52, 'a'), delivery_record(
            4, b'\x42', 52, 0, 0, b'\x52', b'\x62', 0, 100, 2, D_OUT))
    return build


# The pending inbound delivery is queried (DTT_STATUS 8) and never executed;
# the exited one is queried as well; the terminal one is retired on disk;
# the pending outbound token is queried (DTT_INGRESS_STATUS 11); the
# accepted outbound record is retired.
minion('minion-recovers-journals', '0,42,99,0,0', journals=guest_journals(),
       record_kinds=[8, 11],
       expect_files={'inbound/' + delivery_name(b'\x11', 17, 'p'): True,
                     'inbound/' + delivery_name(b'\x12', 18, 't'): False,
                     'outbound/' + delivery_name(b'\x41', 51, 'p'): True,
                     'outbound/' + delivery_name(b'\x42', 52, 'a'): False})
minion('minion-journal-from-other-incarnation', '0,42,99,0,0',
       journals=guest_journals(vmid=41), expect_status=1, live_run=False,
       expect_err='guest journal does not match current VM identity')
minion('minion-journal-wrong-scope', '0,42,99,0,0',
       journals=guest_journals(scope_in=3), expect_status=1, live_run=False,
       expect_err='failed to recover guest delivery ledger: Protocol error')


def mismatched_outbound_spool(state):
    guest_journals()(state)
    put(state / 'outbound', spool_name(b'\x51', b'\x61'), ELF_OUT + b'!')


minion('minion-outbound-spool-mismatch', '0,42,99,0,0',
       journals=mismatched_outbound_spool, expect_status=1, live_run=False,
       expect_err='failed to recover delivery ledger')


# Journal recovery at host startup (scope 0 outbound only; inbound host
# ingest records are recovered by the consumer cohort machinery).
def host_case(name, build, expect_status, expect_err=None):
    with tempfile.TemporaryDirectory(prefix='htd-', dir='/tmp') as root:
        state = Path(root) / 'state'
        for sub in ('', 'inbound', 'outbound', 'base'):
            (state / sub).mkdir(mode=0o700, exist_ok=True)
        build(state)
        env = dict(os.environ, HT_ROOT=root)
        proc = subprocess.Popen([str(binary), '-d', '-D', str(state), '-t', '1'],
                                env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        if expect_status == 0:
            wait_for(os.path.join(root, 'sub.sock'))
            wait_started(proc.pid)
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
        try:
            _, err = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, err = proc.communicate()
        ok = proc.returncode == expect_status and \
            (expect_err is None or expect_err in err)
        results.append({'case': name, 'status': proc.returncode, 'passed': ok,
                        'stderr': err[-600:]})


def host_outbound(scope):
    def build(state):
        put(state / 'outbound', delivery_name(b'\x71', 81, 'p'), delivery_record(
            3, b'\x71', 81, 7, 9, b'\x72', b'\x73', 1001, 4321, scope))
    return build


host_case('host-recovers-forwarder-journal', host_outbound(0), 0)
host_case('host-refuses-guest-outbound-journal', host_outbound(2), 1,
          'failed to recover delivery ledger: Protocol error')


def host_inbound_guest_record(state):
    put(state / 'inbound', delivery_name(b'\x74', 82, 'p'), delivery_record(
        4, b'\x74', 82, 7, 9, b'\x75', b'\x76', 0, 0, 1, D_IN))


host_case('host-refuses-guest-inbound-journal', host_inbound_guest_record, 1,
          'failed to recover guest delivery ledger')



def guest_publish(root, state):
    # A guest consumer publishes an ELF for the host: the guest daemon
    # journals the token, asks bhyve for the VM identity, sends the bare ELF
    # through its dttransport writer and retires the token only after the
    # host's DTT_HOST_ELF receipt arrives.
    elf = b'\x7fELF' + bytes(range(100)) * 50	# several DTT fragments
    c = consumer(root)
    frame(c, elf_header(len(elf), b'\x6a'), elf)
    ack = recv_exact(c, 1).hex()
    out_dir = state / 'outbound'
    retired = eventually_true(lambda: not any(
        p.name.startswith('.delivery.') for p in out_dir.iterdir()), 8)
    c.close()
    return {'ok': ack == '01' and retired, 'ack': ack, 'retired': retired}


def eventually_true(predicate, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


minion('minion-guest-publishes-to-host', '0,42,99,0,0', answer=True,
       body=guest_publish, record_kinds=None)


(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
failed = [r for r in results if not r['passed']]
for r in failed:
    print(json.dumps(r, indent=1))
print('daemon-main:', len(results), 'scenarios;', len(failed), 'failures')
raise SystemExit(1 if failed else 0)
