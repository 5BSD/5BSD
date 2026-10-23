#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Peer library for the dtraced process-level drivers (handoff-peers.py,
handoff-sweep.py, live-sweep.py): restartable daemon incarnations on private
roots with an emulated VMM/HyperTrace kernel (HT_VMDIR), VM peers that speak
the bhyve protocol, dtrace(1) host-consumer and connector models, and the
independent encoders the oracles use. Set htpeerlib.binary first."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

binary = None	# set by the driver: the daemon-main test executable

VERSION, HELLO, HEADER = 67, 160, 520
KIND_CONSUMER, KIND_FORWARDER, KIND_DTRACED = 1, 2, 3
SUB_READDATA, SUB_ELFWRITE, SUB_KILL, SUB_CLEANUP = 1, 2, 4, 8
SUB_INFO, SUB_ADMISSION_ACK, SUB_REPLAY_MANIFEST, SUB_SOURCE_RELEASE = 16, 32, 64, 128
MSG_ELF, MSG_KILL, MSG_INSTALLED, MSG_STATUS = 1, 2, 5, 7
MSG_HANDOFF, MSG_HANDOFF_DELIVERY, MSG_HANDOFF_KILL = 10, 11, 12
MSG_HANDOFF_BIND_DELIVERY, MSG_HANDOFF_BIND_KILL = 13, 14
MSG_HANDOFF_CLEANUP, MSG_HANDOFF_IMPORT = 17, 19
MSG_CONSUMER_PROGRAM, MSG_HANDOFF_RELEASE_IMPORT = 20, 22
OPS = dict(PREPARE=1, COMMIT=2, ABORT=3, RESERVE=4, CANCEL=5, MUTATE=6,
           CLAIM=7, SOURCE_STATUS=8, DESTINATION_STATUS=9, BIND_KILLS_ALL=10,
           REKEY_APPLIED=11, EXPORT=12, PROMOTE_IMPORT=13, ACTIVATE_IMPORT=14,
           SOURCE_RELEASE=15, SOURCE_GATE_BEGIN=16, SOURCE_GATE_ABORT=17,
           SOURCE_DRAIN_STEP=18, RELEASE_RECOVER=19, REPLAY_READY=20,
           EXECUTION_START=21, REBIND_BEGIN=22, REBIND_STAGE=23,
           REBIND_PENDING=24, REBIND_CANCEL_PENDING=25, REBIND_COMMIT_EMPTY=26,
           REBIND_EMPTY_READY=27, RESET_MUTATION=28,
           REBIND_NONEMPTY_PREFLIGHT=29)
ZERO32 = bytes(32)


def recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError(len(data))
        data.extend(chunk)
    return bytes(data)


def hello(kind, subs, ident, session=b''):
    return (struct.pack('<IIQ', kind, VERSION, subs) +
            ident.encode().ljust(128, b'\0') + session.ljust(16, b'\0'))


def header(kind, length=0):
    h = bytearray(HEADER)
    struct.pack_into('<QQ', h, 0, kind, length)
    return h


def frame(sock, head, body=b''):
    sock.sendall(struct.pack('<Q', len(head) + len(body)) + bytes(head) + body)


def make_keys(directory, name):
    priv = directory / (name + '.pem')
    pub = directory / (name + '.pub')
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'ed25519', '-out',
                    str(priv)], check=True, capture_output=True)
    subprocess.run(['openssl', 'pkey', '-in', str(priv), '-pubout', '-out',
                    str(pub)], check=True, capture_output=True)
    os.chmod(priv, 0o600)
    os.chmod(pub, 0o644)
    return priv, pub


class Daemon:
    """One host: a private root, journals, emulated kernel; restartable."""

    def __init__(self, name, extra_args=(), copy_from=None, env=None):
        self.tmp = tempfile.TemporaryDirectory(prefix='htp-', dir='/tmp')
        self.root = self.tmp.name
        self.name = name
        self.vmdir = Path(self.root) / 'vms'
        self.env = dict(env or {})
        if copy_from is not None:
            # a later incarnation on a copy of another root's journals and
            # emulated kernel state (snapshots for fault sweeps)
            for sub in ('state', 'vms', 'keys'):
                if (Path(copy_from) / sub).exists():
                    shutil.copytree(Path(copy_from) / sub, Path(self.root) / sub,
                                    symlinks=True)
            extra_args = [a.replace(str(copy_from), self.root) for a in extra_args]
        else:
            self.vmdir.mkdir()
        self.extra = list(extra_args)
        self.proc = None
        self.logs = []
        self.incarnations = 0

    @property
    def state(self):
        return Path(self.root) / 'state'

    def start(self):
        env = dict(os.environ, HT_ROOT=self.root, HT_VMDIR=str(self.vmdir),
                   **self.env)
        self.err = open(os.path.join(self.root, 'stderr.%d' % self.incarnations), 'w+')
        self.proc = subprocess.Popen(
            [str(binary), '-d', '-D', str(self.state), '-t', '4', *self.extra],
            env=env, stdout=subprocess.DEVNULL, stderr=self.err)
        self.incarnations += 1
        sock = os.path.join(self.root, 'sub.sock')
        end = time.monotonic() + 15
        while not os.path.exists(sock):
            if self.proc.poll() is not None or time.monotonic() > end:
                raise RuntimeError('%s did not start (%s)' % (self.name, self.proc.poll()))
            time.sleep(0.02)
        self.wait_started()

    def wait_started(self):
        # startup recovery of a large journal under sweep load (12 sanitized
        # daemons) can exceed 15 s; a daemon that exits is reported at once
        end = time.monotonic() + getattr(self, 'start_timeout', 45)
        while time.monotonic() < end:
            p = subprocess.run(['procstat', '-f', str(self.proc.pid)],
                               capture_output=True, text=True)
            kinds = [l.split()[3] for l in p.stdout.splitlines()[1:]
                     if len(l.split()) > 3]
            if kinds.count('k') >= 4:
                return
            if self.proc.poll() is not None:
                break
            time.sleep(0.02)
        raise RuntimeError('%s initialize() did not return' % self.name)

    def stop(self):
        if self.proc is None:
            return 0
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            status = self.proc.wait(timeout=25)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            status = self.proc.wait()
        self.err.seek(0)
        text = self.err.read()
        self.debug = getattr(self, 'debug', []) + [l for l in text.splitlines()
                                                   if l.startswith('DBG ')]
        self.logs.append(text[-1500:])
        for marker in ('Sanitizer', 'runtime error:'):
            at = text.find(marker)
            if at >= 0:
                self.logs.append(text[max(0, at - 300):at + 1500])
                break
        self.err.close()
        self.proc = None
        return status

    def restart(self):
        status = self.stop()
        if status != 0:
            raise RuntimeError('%s exited %s' % (self.name, status))
        self.start()

    def close(self):
        self.stop()
        self.tmp.cleanup()

    def connect(self):
        end = time.monotonic() + 10
        while True:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(15)
            try:
                s.connect(os.path.join(self.root, 'sub.sock'))
                break
            except (ConnectionRefusedError, FileNotFoundError):
                s.close()
                if time.monotonic() > end:
                    raise
                time.sleep(0.02)
        server = recv_exact(s, HELLO)
        assert struct.unpack_from('<IIQ', server) == (KIND_DTRACED, VERSION, 0)
        return s

    def files(self, sub='outbound'):
        d = self.state / sub
        return sorted(p.name for p in d.iterdir()) if d.exists() else []

    def has(self, prefix, sub='outbound'):
        return any(n.startswith(prefix) for n in self.files(sub))


class VM:
    """A VMM instance in the emulated kernel of one host."""

    def __init__(self, host, vmid, epoch, name, session, create=True):
        self.host, self.vmid, self.epoch, self.name = host, vmid, epoch, name
        self.session = session.ljust(16, b'\0')
        self.path = host.vmdir / ('vm.%d.%d.%s' % (vmid, epoch, name))
        if create:
            self.path.write_bytes(b'')
        self.fd = os.open(self.path, os.O_RDONLY) if self.path.exists() else -1

    def rebind(self, host):
        """The same VM on another root (a snapshot copy)."""
        return VM(host, self.vmid, self.epoch, self.name, self.session, create=False)

    def destroy(self):
        # The VMM is gone: attestation and the epoch's liveness end.
        self.path.unlink()

    def channel(self, subs=SUB_READDATA):
        s = self.host.connect()
        s.sendall(hello(KIND_FORWARDER, subs, self.name, self.session))
        socket.send_fds(s, [b'\xa5'], [self.fd])
        return s

    def handoff(self, op, token, digest=ZERO32, reply=None):
        """One bhyve ht_handoff_fresh request. Returns (ack, reply)."""
        s = self.channel()
        try:
            body = bytes([OPS[op]]) + token + digest
            frame(s, header(MSG_HANDOFF), body)
            ack = s.recv(1)
            if ack != b'\1':
                return (ack.hex() if ack else 'eof', None)
            if reply == 'status':
                return ('01', decode_status(recv_exact(s, 48)))
            if reply == 'transfer':
                length, = struct.unpack('<Q', recv_exact(s, 8))
                return ('01', recv_exact(s, length))
            if reply == 'step':
                return ('01', recv_exact(s, 1)[0])
            return ('01', None)
        finally:
            s.close()


def decode_status(w):
    did, = struct.unpack_from('<Q', w, 0)
    return dict(delivery=did, phase=chr(w[8]) if w[8] else '', revoked=w[9],
                replay=w[10], reserved=w[11:16], digest=w[16:48])


def transfer_valid(bundle, token):
    """Independent HTX1 checks: magic, token binding, SHA-256 trailer."""
    return (len(bundle) >= 64 and bundle[:4] == b'HTX1' and token in bundle[:32]
            and hashlib.sha256(bundle[:-32]).digest() == bundle[-32:])


def release_valid(wire, token, checkpoint, transfer_digest):
    """bhyve's ht_release_reply_valid plus the transfer binding."""
    return (len(wire) == 324 and wire[:4] == b'HSA1' and wire[4] == 1 and
            wire[5:8] == bytes(3) and wire[8:40] != ZERO32 and
            wire[40:72] != ZERO32 and wire[72:80] == b'HSL1HTH2' and
            wire[80:96] == token and wire[122:154] == checkpoint and
            wire[154:164] == bytes(10) and wire[164:196] == transfer_digest and
            hashlib.sha256(wire[76:196]).digest() == wire[196:228] and
            hashlib.sha256(wire[72:228]).digest() == wire[228:260])


MSG_CONSUMER_DRAIN, MSG_CONSUMER_STOP = 21, 23
MSG_CONSUMER_EXECUTION, MSG_KILL_APPLIED = 16, 9
import threading


class Connector:
    """bhyve's restored-VM data connector (ELFWRITE|KILL|ADMISSION_ACK|
    REPLAY_MANIFEST): reads the admission ACK and replay manifest, then
    queues every ELF frame and acknowledges it with its delivery ID."""

    def __init__(self, vm):
        self.sock = vm.channel(SUB_ELFWRITE | SUB_KILL | SUB_ADMISSION_ACK |
                               SUB_REPLAY_MANIFEST)
        self.admission = recv_exact(self.sock, 1).hex()
        count, = struct.unpack('<I', recv_exact(self.sock, 4))
        self.manifest = [recv_exact(self.sock, 32) for _ in range(count)]
        self.frames, self.kills = [], []
        self.sock.settimeout(None)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        try:
            while True:
                h = recv_exact(self.sock, HEADER)
                kind, length, delivery = struct.unpack_from('<QQQ', h, 0)
                if kind == MSG_ELF:
                    body = recv_exact(self.sock, length)
                    self.frames.append((delivery, bytes(h[24:40]), bytes(h[40:56]), body))
                    self.sock.sendall(struct.pack('<Q', delivery))
                elif kind == MSG_KILL:
                    self.kills.append(bytes(h))
                else:
                    recv_exact(self.sock, length)
        except (EOFError, OSError):
            return

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        self.thread.join(5)


class HostConsumer:
    """A registered HyperTrace host consumer (dtrace(1) model): receives ELF
    uploads, acknowledges them (no derived program), and answers drain
    challenges exactly as libdtrace does."""

    def __init__(self, host, session=b'\xc1', program=b'compiled program'):
        self.host = host
        self.session = session.ljust(16, b'\0')
        self.birth = os.urandom(16).hex()
        self.ident = 'dtrace-%d-%s' % (os.getpid(), self.birth)
        self.digest = hashlib.sha256(program).digest()
        self.received, self.drains, self.stops = [], [], []
        self.executions = []
        self.derived = []
        self.derive = False
        self.execute = True
        self.ingress_session = b'\x42'.ljust(16, b'\0')
        self.lock = threading.Lock()
        self.connect()

    def connect(self):
        self.sock = self.host.connect()
        self.sock.sendall(hello(KIND_CONSUMER, SUB_READDATA | SUB_ELFWRITE,
                                self.ident, self.session))
        frame(self.sock, header(MSG_CONSUMER_PROGRAM, 32), self.digest)
        self.registered = recv_exact(self.sock, 1)
        self.sock.settimeout(None)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        try:
            while True:
                h = recv_exact(self.sock, HEADER)
                kind, length = struct.unpack_from('<QQ', h, 0)
                body = recv_exact(self.sock, length)
                if kind == MSG_ELF:
                    delivery, = struct.unpack_from('<Q', h, 16)
                    vmid, = struct.unpack_from('<H', h, 64)
                    epoch, = struct.unpack_from('<Q', h, 72)
                    with self.lock:
                        self.received.append((delivery, vmid, epoch, h[24:40],
                                              h[40:56], body))
                    outcome = 1
                    if getattr(self, 'derive', False):
                        # dtrace(1) publishes the derived program for the
                        # uploading VM before it reports the outcome
                        self.derived.append(self.publish_derived(
                            delivery, vmid, epoch, bytes(h[24:40]), bytes(h[40:56])))
                        outcome = 2
                    ack = struct.pack('<Q16s16sHBxxxxxQ', delivery, h[24:40],
                                      h[40:56], vmid, outcome, epoch)
                    self.sock.sendall(ack)
                    if self.execute:
                        if getattr(self, 'report_retry', 0):
                            # dtrace(1) reports from its own thread
                            # (report_identified_executions)
                            t = threading.Thread(
                                target=lambda a=ack: self.executions.append(
                                    self.report_execution(a, self.ingress_session)),
                                daemon=True)
                            t.start()
                        else:
                            self.executions.append(self.report_execution(
                                ack, self.ingress_session))
                elif kind == MSG_CONSUMER_DRAIN:
                    with self.lock:
                        self.drains.append(body)
                    self.sock.sendall(body + b'\1' + bytes(7))
                elif kind == MSG_CONSUMER_STOP:
                    with self.lock:
                        self.stops.append(body)
                    # HSA1 stop proof: magic, echoed challenge, result 1
                    self.sock.sendall(b'HSA1' + bytes(4) + body[8:104] + b'\1' + bytes(7))
                else:
                    with self.lock:
                        self.received.append(('other', kind, body))
        except (EOFError, OSError):
            return

    def publish_derived(self, delivery, vmid, epoch, program, source):
        """A derived program for the parent upload (dtrace_send_elf_derived):
        the parent identity in the installed slot, the HDERIV1 program ID
        (independent encoder) and a target envelope for the uploading VM."""
        elf = b'\x7fELF' + b'derived' * 6
        payload = struct.pack('<IHHQQ', 0x32544748, 2, vmid, epoch, 0) + elf
        pre = b'HDERIV1\0' + self.session + struct.pack('<QHQ', delivery, vmid, epoch) + \
            program + source + hashlib.sha256(payload).digest()
        program_id = hashlib.sha256(pre).digest()[:16]
        h = header(MSG_ELF, len(payload))
        h[24:40] = program_id
        h[40:56] = source
        h[80:88] = b'outbound'
        struct.pack_into('<QHxxxxxxQ', h, 336, delivery, vmid, epoch)
        h[360:376] = program
        h[376:392] = source
        h[392:408] = self.session
        s = self.host.connect()
        try:
            s.sendall(hello(KIND_CONSUMER, SUB_READDATA, self.ident, self.session))
            frame(s, h, payload)
            return (s.recv(1).hex(), program_id)
        except OSError as exc:
            return (repr(exc), program_id)
        finally:
            s.close()

    def report_execution(self, ack, ingress_session, retry_seconds=None):
        """dtrace(1)'s execution report on a one-shot second channel. Like
        report_identified_execution() in dtrace.c, a refused or failed
        attempt is repeated every 100 ms until accepted or the deadline
        (dtrace(1): 60 s; retry_seconds, default self.report_retry or 0 for
        a single attempt) passes; the last status is returned."""
        if retry_seconds is None:
            retry_seconds = getattr(self, 'report_retry', 0)
        deadline = time.monotonic() + retry_seconds
        while True:
            try:
                s = self.host.connect()
            except OSError as exc:
                status = repr(exc)
            else:
                try:
                    s.sendall(hello(KIND_CONSUMER, SUB_READDATA, self.ident,
                                    self.session))
                    frame(s, header(MSG_CONSUMER_EXECUTION, 72), ack + ingress_session)
                    status = s.recv(1).hex()
                except OSError as exc:
                    status = repr(exc)
                finally:
                    s.close()
            if status == '01' or time.monotonic() >= deadline:
                return status
            time.sleep(0.1)

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        self.thread.join(5)


def wait_until(predicate, seconds=10):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def elf_frame(length, source, location=b'outbound', program=b'', delivery=0):
    h = header(MSG_ELF, length)
    struct.pack_into('<Q', h, 16, delivery)
    h[24:40] = program.ljust(16, b'\0')
    h[40:56] = source.ljust(16, b'\0')
    h[80:80 + len(location)] = location
    return h


def observation(kind, delivery, vm, program, source):
    h = header(kind)
    struct.pack_into('<QHxxxxxxQ', h, 336, delivery, vm.vmid, vm.epoch)
    h[360:376] = program
    h[376:392] = source
    h[392:392 + len(vm.name)] = vm.name.encode()
    return h


def kill_frame(pid, vm, source):
    h = header(MSG_KILL)
    struct.pack_into('<IHxxQ', h, 272, pid, vm.vmid, vm.epoch)
    h[288:304] = source.ljust(16, b'\0')
    return h


def publish(host, writer, consumer, elf, source):
    """Consumer publishes; the VM's ELFWRITE channel receives and ACKs."""
    frame(consumer, elf_frame(len(elf), source), elf)
    ack = recv_exact(consumer, 1)
    h = recv_exact(writer, HEADER)
    kind, length, delivery = struct.unpack_from('<QQQ', h, 0)
    recv_exact(writer, length)
    writer.sendall(struct.pack('<Q', delivery))
    return ack, delivery, bytes(h[24:40]), bytes(h[40:56])


def guest_upload(vm, sock, delivery, program, source, elf):
    name = vm.name.encode()
    body = struct.pack('<IHHQQ', 0x32565448, 2, vm.vmid, vm.epoch, len(name)) + name + elf
    frame(sock, elf_frame(len(body), source, b'inbound', program, delivery), body)
    return recv_exact(sock, 1), body


def request(vm, kind, body, status=True):
    """One attested request with a 48-byte status reply (bhyve lookups)."""
    s = vm.channel()
    try:
        frame(s, header(kind), body)
        ack = s.recv(1)
        if ack != b'\1':
            return (ack.hex() if ack else 'eof', None)
        return ('01', decode_status(recv_exact(s, 48)) if status else None)
    finally:
        s.close()


def delivery_wire(token, checkpoint, delivery, program, source, scope=0,
                  payload=None):
    w = token + checkpoint + struct.pack('<Q', delivery) + \
        program.ljust(16, b'\0') + source.ljust(16, b'\0') + bytes([scope]) + bytes(7)
    return w + payload if payload is not None else w


def kill_wire(token, checkpoint, pid, source):
    return token + checkpoint + struct.pack('<I', pid) + source.ljust(16, b'\0') + bytes(4)


def raw_public(pub_pem):
    der = subprocess.run(['openssl', 'pkey', '-pubin', '-in', str(pub_pem),
                          '-outform', 'DER'], check=True, capture_output=True).stdout
    return der[-32:]


def hth2(token, session, vmid, epoch, checkpoint, transfer, dvmid=0, depoch=0):
    """Independent encoder of the HTH2 handoff record (152 bytes)."""
    b = bytearray(152)
    b[0:4] = b'HTH2'
    b[4:20] = token
    b[20:36] = session.ljust(16, b'\0')
    struct.pack_into('<HQ', b, 36, vmid, epoch)
    b[46:78] = checkpoint
    struct.pack_into('<HQ', b, 78, dvmid, depoch)
    b[88:120] = transfer
    b[120:152] = hashlib.sha256(bytes(b[:120])).digest()
    return bytes(b)


def hsa1(source_key, source_pub, destination_pub, token, session, vmid, epoch,
         checkpoint, transfer, tmpdir):
    """A foreign source host's signed release (HSA1 over HSL1), produced
    with openssl's Ed25519 signer, not the daemon's code."""
    hsl = b'HSL1' + hth2(token, session, vmid, epoch, checkpoint, transfer)
    hsl = hsl + hashlib.sha256(hsl).digest()
    assert len(hsl) == 188
    unsigned = b'HSA1' + bytes([1, 0, 0, 0]) + raw_public(source_pub) + \
        raw_public(destination_pub) + hsl
    assert len(unsigned) == 260
    msg = Path(tmpdir) / 'hsa1.msg'
    msg.write_bytes(unsigned)
    sig = subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey',
                          str(source_key), '-in', str(msg)], check=True,
                         capture_output=True).stdout
    assert len(sig) == 64
    return unsigned + sig


def populate_source(host, src, d, upload=True, journal=True):
    """Give a source VM a settled outbound journal and an executed host
    ingest; returns the objects later steps need."""
    ctx = {}
    writer = src.channel(SUB_ELFWRITE)
    reader = src.channel(SUB_READDATA | SUB_KILL)
    time.sleep(0.2)
    if journal:
        pub = host.connect()
        pub.sendall(hello(KIND_CONSUMER, SUB_READDATA, 'dtracedctl-%d' % os.getpid()))
        ctx['elf1'] = b'\x7fELF' + bytes(range(48))
        ack, ctx['del1'], ctx['prog1'], ctx['src1'] = publish(host, writer, pub, ctx['elf1'], b'\x51')
        ctx['elf2'] = ctx['elf1'] + b'2'
        ack, ctx['del2'], ctx['prog2'], ctx['src2'] = publish(host, writer, pub, ctx['elf2'], b'\x52')
        time.sleep(0.2)
        frame(reader, observation(MSG_INSTALLED, ctx['del1'], src, ctx['prog1'], ctx['src1']))
        d['installed'] = recv_exact(reader, 1).hex()
        frame(pub, kill_frame(4242, src, b'\x53'))
        d['kill'] = recv_exact(pub, 1).hex()
        kh = bytearray(recv_exact(reader, HEADER))
        struct.pack_into('<Q', kh, 0, MSG_KILL_APPLIED)
        frame(reader, kh)
        d['kill_applied'] = recv_exact(reader, 1).hex()
        pub.close()
    if upload:
        ctx['hc'] = HostConsumer(host)
        ctx['up_elf'] = b'\x7fELF' + b'upload' * 8
        ack, ctx['up_body'] = guest_upload(src, reader, 601, b'\xa1', b'\xb1', ctx['up_elf'])
        d['upload'] = ack.hex()
        d['executed'] = wait_until(lambda: ctx['hc'].executions == ['01'])
    ctx['writer'], ctx['reader'] = writer, reader
    return ctx
