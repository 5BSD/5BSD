#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Fault sweeps over live dtraced flows in real daemon incarnations.

Usage: live-sweep.py BINARY OUTPUT [FLOW ...] [--kinds sys,oom] [--jobs N]
                     [--entries handle,send_elf,...]

BINARY is the daemon-main test executable (actual dtraced objects plus the
daemon-main.cc shim). Flows are the daemon's live work, driven by peers that
speak the real protocols (htpeerlib.py): an outbound program delivery
(publish, guest queue ACK, installation, KILL with its applied report,
uninstallation, a cleanup request with the guest's queue ACK and applied
report), a host ingest (guest upload, host consumer delivery, ACK and
execution report, and a lost consumer ACK settled on reconnect) and a
fresh-session stop (collector stop challenge, stop steps, release).

The reference run snapshots every host's journals and emulated kernel state
before each step. For each step, each daemon entry point that runs work
(client_request::handle, job::read_data, send_elf, send_kill, send_cleanup,
send_info, process_inbound, process_outbound) and each N, a new incarnation
starts on a copy of the snapshot, and the N-th file-system call ("sys") or
allocation ("oom") made inside that entry fails once (HT_FAULT_FILE).

Oracles for every injected point:
  * no sanitizer report, and every incarnation exits 0;
  * after the failure, a restarted incarnation on the same journals, with
    the peers reconnected and the step's action retried as its real peer
    would (idempotent requests are resent; queue ACKs are resent on replay),
    converges to the reference: the step's reply equals the reference reply
    and the canonical journal state (record kinds and phases in every journal
    directory, identifiers abstracted) equals the reference state;
  * when the fault never fired, the step's reply and the canonical state
    equal the reference.
"""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import sys
import threading
import time
import traceback

args = list(sys.argv[1:])
mode = 'fault'
if '--mode' in args:
    i = args.index('--mode')
    mode = args[i + 1]
    del args[i:i + 2]
assert mode in ('fault', 'corrupt', 'hostile', 'startup', 'guest-startup', 'callfault')
reference_only = '--reference-only' in args
if reference_only:
    args.remove('--reference-only')
point = None
if '--point' in args:
    i = args.index('--point')
    point = args[i + 1].split(':')
    del args[i:i + 2]
opts = {'--kinds': 'sys,oom', '--jobs': str(max(2, (os.cpu_count() or 4) // 2)),
        '--entries': 'all', '--steps': 'all'}
for key in list(opts):
    if key in args:
        i = args.index(key)
        opts[key] = args[i + 1]
        del args[i:i + 2]
kinds = opts['--kinds'].split(',')
jobs = int(opts['--jobs'])
entries = None if opts['--entries'] == 'all' else opts['--entries'].split(',')
steps = None if opts['--steps'] == 'all' else opts['--steps'].split(',')
KEEP_LOGS = os.environ.get('LS_KEEP_LOGS') == '1'
binary, out = Path(args[0]).resolve(), Path(args[1]).resolve()
selected = args[2:]
assert binary.is_relative_to('/usr/obj') and out.is_relative_to('/usr/obj')
out.mkdir(parents=True, exist_ok=True)
_binary, _out = binary, out
sys.path.insert(0, str(Path(__file__).resolve().parent))
import htpeerlib
from htpeerlib import *
binary, out = _binary, _out
htpeerlib.binary = binary

MSG_CLEANUP, MSG_UNINSTALLED, MSG_CLEANUP_APPLIED = 3, 6, 18
MSG_SESSION_STOP, MSG_SESSION_RELEASE, MSG_CONSUMER_STOP_COMMIT = 24, 25, 26
SANITIZER = ('AddressSanitizer', 'runtime error:', 'LeakSanitizer')


# ---------------------------------------------------------------- peers
class Guest:
    """One VM's channels in one incarnation: an ELFWRITE writer that queues
    and ACKs every program, and a READDATA|KILL|CLEANUP listener that
    reports KILLs applied and ACKs and applies cleanups (fresh channels for
    the reports, as bhyve does)."""

    def __init__(self, vm, ack_programs=True, unacked=None, ledger=None):
        self.vm = vm
        # every (program, delivery) frame received by this VM lifetime,
        # across daemon incarnations
        self.ledger = ledger if ledger is not None else []
        # completions (KILL/CLEANUP applied) the daemon did not acknowledge;
        # bhyve keeps them and reports them again after reconnecting
        self.unacked = unacked if unacked is not None else []
        self.programs, self.kills, self.cleanups = [], [], []
        self.reports = []
        self.ack_programs = ack_programs
        # bhyve's two channels (usr.sbin/bhyve/hypertrace.c ht_connect):
        # rx receives ELF, KILL and CLEANUP frames with the admission ACK and
        # replay manifest; wx (READDATA) carries the guest's uploads
        self.writer = vm.channel(SUB_ELFWRITE | SUB_KILL | SUB_CLEANUP |
                                 SUB_ADMISSION_ACK | SUB_REPLAY_MANIFEST)
        self.admission = recv_exact(self.writer, 1).hex()
        count, = struct.unpack('<I', recv_exact(self.writer, 4))
        self.manifest = [recv_exact(self.writer, 32) for _ in range(count)]
        self.listener = vm.channel(SUB_READDATA | SUB_ADMISSION_ACK)
        self.listener_admission = recv_exact(self.listener, 1).hex()
        for sock in (self.writer, self.listener):
            sock.settimeout(None)
        self.reporters = []
        self.threads = [threading.Thread(target=self.serve_writer, daemon=True)]
        for t in list(self.threads):
            t.start()

    def serve_writer(self):
        try:
            while True:
                h = bytearray(recv_exact(self.writer, HEADER))
                kind, length, delivery = struct.unpack_from('<QQQ', h, 0)
                if kind == MSG_KILL:
                    self.kills.append(bytes(h[272:304]))
                    struct.pack_into('<Q', h, 0, MSG_KILL_APPLIED)
                    struct.pack_into('<Q', h, 8, 0)
                    self.report(h)
                    continue
                if kind == MSG_CLEANUP:
                    self.serve_cleanup(self.writer, h)
                    continue
                body = recv_exact(self.writer, length)
                if kind == MSG_ELF:
                    self.ledger.append((bytes(h[24:40]), delivery))
                    self.programs.append((delivery, bytes(h[24:40]), bytes(h[40:56]),
                                          hashlib.sha256(body).hexdigest()))
                    if self.ack_programs:
                        self.writer.sendall(struct.pack('<Q', delivery))
        except (EOFError, OSError):
            return

    def report(self, head):
        # bhyve reports from its guest-control path, never from the reader:
        # report on a separate thread so the listener keeps reading frames
        t = threading.Thread(target=self._report, args=(bytes(head),), daemon=True)
        t.start()
        self.reporters.append(t)

    def _report(self, head):
        try:
            s = self.vm.channel()
            frame(s, head)
            ack = s.recv(1).hex()
            s.close()
        except OSError as exc:
            ack = repr(exc)
        self.reports.append(ack)
        if ack != '01':
            self.unacked.append(bytes(head))

    def report_again(self):
        pending, self.unacked[:] = list(self.unacked), []
        for head in pending:
            self._report(head)

    def serve_cleanup(self, sock, h):
        count, = struct.unpack_from('<Q', h, 304)
        for _ in range(count):
            n, = struct.unpack('<Q', recv_exact(sock, 8))
            recv_exact(sock, n)
        vmid, = struct.unpack_from('<H', h, 312)
        epoch, token = struct.unpack_from('<QQ', h, 320)
        self.cleanups.append(token)
        sock.sendall(struct.pack('<Q', token))
        a = header(MSG_CLEANUP_APPLIED)
        struct.pack_into('<H', a, 312, vmid)
        struct.pack_into('<QQ', a, 320, epoch, token)
        self.report(a)

    def serve_listener(self):
        try:
            while True:
                h = bytearray(recv_exact(self.listener, HEADER))
                kind, = struct.unpack_from('<Q', h, 0)
                if kind == MSG_KILL:
                    self.kills.append(bytes(h[272:304]))
                    struct.pack_into('<Q', h, 0, MSG_KILL_APPLIED)
                    struct.pack_into('<Q', h, 8, 0)
                    self.report(h)
                elif kind == MSG_CLEANUP:
                    self.serve_cleanup(self.listener, h)
                else:
                    length, = struct.unpack_from('<Q', h, 8)
                    recv_exact(self.listener, length)
        except (EOFError, OSError):
            return

    def close(self):
        for sock in (self.writer, self.listener):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        for t in self.threads + self.reporters:
            t.join(5)


def control(host):
    """A root dtracedctl-like consumer (statistics, cleanup, KILL)."""
    c = host.connect()
    c.sendall(hello(KIND_CONSUMER, SUB_READDATA, 'dtracedctl-%d' % os.getpid()))
    return c


def control_request(host, head, body=b''):
    c = control(host)
    try:
        frame(c, head, body)
        return c.recv(1).hex()
    except OSError as exc:
        return repr(exc)
    finally:
        c.close()


def cleanup_frame(names):
    h = header(MSG_CLEANUP)
    struct.pack_into('<Q', h, 304, len(names))
    body = b''.join(struct.pack('<Q', len(n) + 1) + n.encode() + b'\0' for n in names)
    return h, body


def canonical(world):
    """Journal kinds and phases per directory, identifiers abstracted."""
    state = {}
    for name, h in sorted(world.hosts.items()):
        root = Path(h.root) / 'state'
        for d in sorted(p for p in root.rglob('*') if p.is_dir()) + [root]:
            entries = []
            for p in d.iterdir():
                n = p.name
                if n.startswith('.handoff-tmp.') or n.endswith('.lock') or \
                        n.startswith('.elf.') or n.startswith('.tmp') or p.is_dir():
                    continue
                entries.append(re.sub(r'[0-9a-f]{8,}', 'X', n))
            key = name + ':' + str(d.relative_to(root))
            if world.flow.get('fixture_outbound') and key.endswith(':outbound'):
                # the flow republishes an identical fixture program in
                # every incarnation; its count is not part of the oracle
                entries = sorted(set(entries))
            if entries:
                state[key] = sorted(entries)
    return state


# ---------------------------------------------------------------- world
class World:
    def __init__(self, flow, copy_from=None, fault=False):
        self.flow, self.hosts, self.vms, self.peers = flow, {}, {}, []
        for name in flow['hosts']:
            env = {'HT_PEER_ROOT': '1'}
            extra = []
            if flow.get('guest'):
                # a guest (minion) daemon on the shim's scripted transport;
                # host-side records are injected through HT_DTT_INJECT
                # bhyve's transport answers the cleanup-state query (no
                # cleanup in progress); without it a guest with a recorded
                # child refuses to start (cannot prove cleanup state)
                env = {'HT_DTT_IDENTITY': '0,42,99,0,0', 'HT_DTT_ANSWER': '1',
                       'HT_DTT_ACK': '1', 'HT_PD_BIRTH': '1',
                       'HT_DTT_CLEANUP': '0,0,0,0,0',
                       'HT_EXEC_FAKE': flow.get('exec_fake', '1'),
                       'HT_EXEC_FAKE_HOLD_MS': flow.get('exec_hold', '500')}
                extra = ['-m']
            h = Daemon(name, extra, copy_from=None if copy_from is None else copy_from[name],
                       env=env)
            if flow.get('guest'):
                state = Path(h.root) / 'state'
                for d in ('', 'inbound', 'outbound'):
                    (state / d).mkdir(mode=0o700, exist_ok=True)
                h.env['HT_DTT_INJECT'] = os.path.join(h.root, 'inject.sock')
                h.env['HT_DTT_LOG'] = os.path.join(h.root, 'dtt.log')
                h.env['HT_DTT_HOST_DB'] = os.path.join(h.root, 'host-ingest.db')
                h.env['HT_EXEC_LOG'] = os.path.join(h.root, 'exec.log')
            if fault:
                h.env['HT_FAULT_FILE'] = os.path.join(h.root, 'fault')
            self.hosts[name] = h

    def step_env(self, step):
        # per-step daemon environment (e.g. the VM identity bhyve reports
        # after a restore); applies to every later incarnation of the step
        for h in self.hosts.values():
            h.env.update(self.flow.get('step_env', {}).get(step, {}))

    def start(self, step=None):
        if step is not None:
            self.step_env(step)
        for h in self.hosts.values():
            h.start()

    def stop(self):
        for p in self.peers:
            p.close()
        self.peers = []
        return {name: h.stop() for name, h in self.hosts.items()}

    def close(self):
        keep = os.environ.get('LS_KEEP_WORLD')
        for h in self.hosts.values():
            if keep:
                shutil.copytree(h.root, os.path.join(keep, os.path.basename(h.root)),
                                symlinks=True, dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns('*.sock'))
            h.close()

    def logs(self):
        return '\n'.join('\n'.join(h.logs) for h in self.hosts.values())


def vm_for(world, name, vmid, epoch, session):
    h = world.hosts['host']
    path = h.vmdir / ('vm.%d.%d.guest-a' % (vmid, epoch))
    v = VM(h, vmid, epoch, 'guest-a', session, create=not path.exists())
    world.vms[name] = v
    return v


def inject(world, line):
    path = world.hosts['host'].env['HT_DTT_INJECT']
    if not wait_until(lambda: os.path.exists(path), 5):
        return 'no-socket'
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    try:
        s.connect(path)
        s.sendall(line.encode() + b'\n')
        return s.recv(16).decode().strip()
    except OSError as exc:
        return repr(exc)
    finally:
        s.close()


def attach(world, ctx):
    """Peers of one incarnation: the guest's channels and, when the flow
    has one, the host consumer (same dtrace(1) identity every time)."""
    if world.flow.get('guest'):
        time.sleep(0.3)
        return
    v = vm_for(world, 'S', 7, 9, b'\x42')
    g = Guest(v, ack_programs=ctx.get('ack_programs', True),
              unacked=world.__dict__.setdefault('unacked_reports', []),
              ledger=world.__dict__.setdefault('guest_ledger', []))
    world.peers.append(g)
    world.guest = g
    g.report_again()
    if world.flow.get('consumer'):
        hc = HostConsumer.__new__(HostConsumer)
        hc.__dict__.update(dict(host=world.hosts['host'],
                                session=b'\xc1'.ljust(16, b'\0'),
                                birth=ctx['birth'], ident=ctx['ident'],
                                digest=hashlib.sha256(b'compiled program').digest(),
                                received=[], drains=[], stops=[], executions=[],
                                derived=[], derive=world.flow.get('derive', False),
                                execute=ctx.get('execute', True),
                                report_retry=15,
                                ingress_session=b'\x42'.ljust(16, b'\0'),
                                lock=threading.Lock()))
        hc.connect()
        world.peers.append(hc)
        world.consumer = hc
    time.sleep(0.2)


# ---------------------------------------------------------------- flows
def step_publish(world, ctx):
    before = len(world.guest.programs)
    c = control(world.hosts['host'])
    try:
        frame(c, elf_frame(len(ctx['elf']), b'\x51'), ctx['elf'])
        ack = c.recv(1).hex()
    finally:
        c.close()
    wait_until(lambda: len(world.guest.programs) > before, 5)
    if len(world.guest.programs) > before:
        ctx.setdefault('delivery', world.guest.programs[-1])
    return [ack]


def converge_publish(world, ctx):
    # A pending delivery is replayed to the reconnected guest; a publication
    # that never reached the guest is republished, as dtrace(1) would.
    if not wait_until(lambda: published(world, ctx), 3):
        return step_publish(world, ctx)
    return ['01']


def published(world, ctx):
    out_dir = Path(world.hosts['host'].root) / 'state' / 'outbound'
    return bool(world.guest.programs) or any(
        n.startswith('.delivery.') and n.endswith('.a') for n in os.listdir(out_dir))


def killed(world, ctx):
    return any(n.startswith('.killack.') for n in
               os.listdir(Path(world.hosts['host'].root) / 'state' / 'outbound'))


def cleaned(world, ctx):
    return any(n.startswith('.cleanup.') and n.endswith('.g') for n in
               os.listdir(Path(world.hosts['host'].root) / 'state' / 'outbound'))


def executed(world, ctx):
    return any(n.endswith('.N') and n.startswith('.consumer.') for n in
               os.listdir(Path(world.hosts['host'].root) / 'state' / 'inbound')) and \
        len([n for n in os.listdir(Path(world.hosts['host'].root) / 'state' / 'inbound')
             if n.startswith('.consumer.') and n.endswith('.N')]) >= ctx.get('uploads', 1)


def observe(kind):
    def run(world, ctx):
        delivery, program, source, _ = ctx['delivery']
        s = world.vms['S'].channel()
        try:
            frame(s, observation(kind, delivery, world.vms['S'], program, source))
            return [s.recv(1).hex()]
        finally:
            s.close()
    return run


def step_kill(world, ctx):
    before = len(world.guest.kills)
    ack = control_request(world.hosts['host'], kill_frame(4242, world.vms['S'], b'\x51'))
    wait_until(lambda: len(world.guest.kills) > before and
               len(world.guest.reports) >= len(world.guest.kills), 5)
    return [ack]


def step_cleanup(world, ctx):
    before = len(world.guest.cleanups)
    h, body = cleanup_frame(['guest-a'])
    ack = control_request(world.hosts['host'], h, body)
    wait_until(lambda: cleaned(world, ctx), 30)
    return [ack]


def step_upload(delivery, program, source):
    def run(world, ctx):
        ack, _ = guest_upload(world.vms['S'], *(_fresh(world)), delivery, program,
                              source, b'\x7fELF' + program * 8)
        return [ack.hex()]
    return run


def _fresh(world):
    s = world.vms['S'].channel()
    world.peers.append(type('closer', (), {'close': lambda self, s=s: s.close()})())
    return (s,)


def settle_executed(world, ctx):
    wait_until(lambda: any(x == '01' for x in world.consumer.executions), 5)


def step_upload_settled(delivery, program, source):
    up = step_upload(delivery, program, source)

    def run(world, ctx):
        reply = up(world, ctx)
        settle_executed(world, ctx)
        return reply
    return run


def executed2(world, ctx):
    d = Path(world.hosts['host'].root) / 'state' / 'inbound'
    return len([n for n in os.listdir(d) if n.startswith('.consumer.') and
                n.endswith('.N')]) >= 2


def derived_done(world, ctx):
    d = Path(world.hosts['host'].root) / 'state'
    return any(n.endswith('.D') for n in os.listdir(d / 'inbound')) and \
        any(n.startswith('.delivery.') and n.endswith('.a') for n in os.listdir(d / 'outbound'))


def step_upload_derived(world, ctx):
    reply = step_upload_settled(601, b'\xa1', b'\xb1')(world, ctx)
    wait_until(lambda: world.guest.programs, 5)
    if world.guest.programs:
        ctx.setdefault('derived_delivery', world.guest.programs[-1])
    return reply


def observe_derived(kind):
    def run(world, ctx):
        if 'derived_delivery' not in ctx:
            programs = world.guest.programs
            wait_until(lambda: programs, 3)
            if programs:
                ctx['derived_delivery'] = programs[-1]
        delivery, program, source, _ = ctx['derived_delivery']
        s = world.vms['S'].channel()
        try:
            frame(s, observation(kind, delivery, world.vms['S'], program, source))
            return [s.recv(1).hex()]
        finally:
            s.close()
    return run


def guest_files(world, sub='inbound'):
    return os.listdir(Path(world.hosts['host'].root) / 'state' / sub)


def guest_elf(world, ctx):
    elf = Path(world.hosts['host'].root) / 'host-program.elf'
    elf.write_bytes(b'\x7fELF' + bytes(range(256)) * 12)
    reply = inject(world, 'elf 900 42 99 %s %s %s' % ('a1' * 16, 'b1' * 16, elf))
    wait_until(lambda: any(n.startswith('.delivery.') and n.endswith('.x')
                           for n in guest_files(world)), 5)
    return [reply]


def guest_launched(world, ctx):
    return any(n.startswith('.delivery.') and n.endswith('.x') for n in guest_files(world))


def guest_kill(world, ctx):
    reply = inject(world, 'kill 4242 42 99 %s' % ('b1' * 16))
    wait_until(lambda: any(n.startswith('.killack.') for n in guest_files(world)), 5)
    return [reply]


def guest_killed(world, ctx):
    return any(n.startswith('.killack.') for n in guest_files(world))


def guest_upload_host(world, ctx):
    # the guest's dtrace -Y returns its linked program to "outbound"; the
    # guest daemon ships it over the transport and the host accepts it
    c = control(world.hosts['host'])
    try:
        body = b'\x7fELF' + b'guest-linked' * 8
        frame(c, elf_frame(len(body), b'\xc9'), body)
        ack = c.recv(1).hex()
    finally:
        c.close()
    wait_until(lambda: guest_shipped(world, ctx), 10)
    return [ack]


def guest_shipped(world, ctx):
    # shipped: the transport carried ELF records (DTT_ELF = 1) and the
    # accepted outbound record was retired (no delivery record remains)
    h = world.hosts['host']
    names = guest_files(world, 'outbound')
    try:
        lines = Path(h.env['HT_DTT_LOG']).read_text().splitlines()
    except OSError:
        lines = []
    return (any(n.startswith('elf.') for n in names) and
            not any(n.startswith('.delivery.') for n in names) and
            any(line.startswith('1 ') for line in lines))


def converge_guest_upload(world, ctx):
    # the publication was acknowledged; a retry would publish a second
    # program, so convergence only waits for the guest daemon to ship it
    if not any(n.startswith('elf.') for n in guest_files(world, 'outbound')):
        return guest_upload_host(world, ctx)   # refused: the publisher retries
    return ['01'] if wait_until(lambda: guest_shipped(world, ctx), 15) else ['unshipped']


def guest_publish_ident(world, ctx):
    # the guest's dtrace(1) -N publishes its program with a program
    # identifier; the daemon ships it and lists the identifier for the
    # launch that will run the host's linked result
    c = control(world.hosts['host'])
    try:
        body = b'\x7fELF' + b'guest-ident' * 8
        h = elf_frame(len(body), b'\xc9')
        struct.pack_into('<I', h, 56, 1)
        ident = b'guest-probe-ident'
        h[144:144 + len(ident)] = ident
        frame(c, h, body)
        ack = c.recv(1).hex()
    finally:
        c.close()
    wait_until(lambda: guest_shipped(world, ctx), 10)
    return [ack]


def dtt_kinds(world):
    try:
        lines = Path(world.hosts['host'].env['HT_DTT_LOG']).read_text().splitlines()
    except OSError:
        return []
    return [line.split()[0] for line in lines if line]


def guest_installed(world, ctx):
    return '4' in dtt_kinds(world)	# DTT_INSTALLED observation


def guest_installed_settled(world, ctx):
    # installed, then exited after its run and retired (also after a
    # daemon crash: the host grants replay and the program runs again)
    return guest_installed(world, ctx) and \
        not any(n.startswith('.delivery.') for n in guest_files(world))


def guest_elf_installed(world, ctx):
    # the identifier list is per incarnation: publish it in this one
    guest_publish_ident(world, ctx)
    reply = guest_elf(world, ctx)
    wait_until(lambda: guest_installed_settled(world, ctx), 15)
    return reply


def guest_live_kill(world, ctx):
    # a KILL for a program whose tracing child is installed and running
    guest_publish_ident(world, ctx)
    elf = Path(world.hosts['host'].root) / 'host-program-2.elf'
    elf.write_bytes(b'\x7fELF' + bytes(range(255, -1, -1)) * 12)
    before = dtt_kinds(world).count('4')
    replies = [inject(world, 'elf 901 42 99 %s %s %s' % ('a2' * 16, 'b2' * 16, elf))]
    wait_until(lambda: dtt_kinds(world).count('4') > before, 10)
    replies.append(inject(world, 'kill 4243 42 99 %s' % ('b2' * 16)))
    wait_until(lambda: guest_live_killed(world, ctx), 10)
    # the killed child's delivery retires once the host acknowledges its
    # uninstall observation
    wait_until(lambda: not any(n.startswith('.delivery.') for n in guest_files(world)), 10)
    return replies


def guest_live_killed(world, ctx):
    return any(n.startswith('.killack.') and n.endswith('b2' * 16)
               for n in guest_files(world))


def guest_rekeyed(world, ctx):
    # the KILL journal now names the new lifetime (vmid 43 = 0x2b)
    return any(n.startswith('.kill.002b.') for n in guest_files(world))


def guest_rekeyed_wait(world, ctx):
    return ['rekeyed' if wait_until(lambda: guest_rekeyed(world, ctx), 10) else 'old']


def guest_elf_new_lifetime(world, ctx):
    elf = Path(world.hosts['host'].root) / 'host-program-3.elf'
    elf.write_bytes(b'\x7fELF' + b'new lifetime' * 30)
    reply = inject(world, 'elf 902 43 100 %s %s %s' % ('a3' * 16, 'b3' * 16, elf))
    wait_until(lambda: guest_launched_new(world, ctx), 5)
    return [reply]


def guest_launched_new(world, ctx):
    try:
        log = Path(world.hosts['host'].env['HT_EXEC_LOG']).read_text()
    except OSError:
        return False
    return ('a3' * 16) in log


def outbound_names(world):
    return os.listdir(Path(world.hosts['host'].root) / 'state' / 'outbound')


def consumer_stop_acked(world, ctx):
    # the stop step collected the consumer's HSA1 proof (FSA1 record)
    return any(n.startswith('.fresh-ack.') for n in outbound_names(world))


def fresh_stop_done(world, ctx):
    return any(n.startswith('.fresh-done.') for n in outbound_names(world))


def gate_suspend(world, ctx):
    # bhyve suspends the VM's DTrace gate before a fresh-session stop
    vmdir = world.hosts['host'].vmdir
    (vmdir / 'gate.7.9').write_bytes(b'\1' + ctx['stop_token'])


def release_setup(world, ctx):
    # The restored VM (a new lifetime) starts with its DTrace gate suspended
    # by the stop token; SESSION_RELEASE resumes it.
    vmdir = world.hosts['host'].vmdir
    (vmdir / 'gate.8.10').write_bytes(b'\1' + ctx['stop_token'])


def session_step(kind):
    def once(world, ctx):
        body = (b'FST1' if kind == MSG_SESSION_STOP else b'FRE1') + bytes(4) + ctx['stop_token']
        v = world.vms['S'] if kind == MSG_SESSION_STOP else \
            vm_for(world, 'D', 8, 10, b'\x43')
        s = v.channel()
        try:
            frame(s, header(kind), body)
            ack = s.recv(1).hex()
            remaining = s.recv(1).hex() if ack == '01' else None
            return [ack, remaining]
        finally:
            s.close()

    def run(world, ctx):
        reply = once(world, ctx)
        # bhyve's stop coordinator repeats SESSION_STOP while collectors
        # remain; a consumer that was not yet registered when the step ran
        # is contacted by a later attempt
        for _ in range(5):
            if kind != MSG_SESSION_STOP or reply != ['01', '01'] or \
                    consumer_stop_acked(world, ctx):
                break
            time.sleep(1)
            reply = once(world, ctx)
        return reply
    return run


def prepare_outbound(world, ctx):
    ctx['elf'] = b'\x7fELF' + bytes(range(48))


def prepare_ingest(world, ctx):
    ctx['birth'] = os.urandom(16).hex()
    ctx['ident'] = 'dtrace-%d-%s' % (os.getpid(), ctx['birth'])


def prepare_fresh(world, ctx):
    prepare_ingest(world, ctx)
    ctx['stop_token'] = hashlib.sha256(b'fresh stop').digest()[:16]


FLOWS = {
    'outbound-delivery': dict(hosts=['host'], prepare=prepare_outbound, steps=[
        ('PUBLISH', step_publish, converge_publish, published),
        ('INSTALLED', observe(MSG_INSTALLED), None, None),
        ('KILL', step_kill, None, killed),
        ('UNINSTALLED', observe(MSG_UNINSTALLED), None, None),
        ('CLEANUP', step_cleanup, None, cleaned),
    ]),
    'host-ingest': dict(hosts=['host'], consumer=True, prepare=prepare_ingest, steps=[
        ('UPLOAD', step_upload_settled(601, b'\xa1', b'\xb1'), None, executed),
        ('UPLOAD_2', step_upload_settled(602, b'\xa2', b'\xb2'), None, executed2),
    ]),
    'derived': dict(hosts=['host'], consumer=True, derive=True, prepare=prepare_ingest,
                    steps=[
        ('UPLOAD', step_upload_derived, None, derived_done),
        ('INSTALLED', observe_derived(MSG_INSTALLED), None, None),
        ('UNINSTALLED', observe_derived(MSG_UNINSTALLED), None, None),
    ]),
    'guest': dict(hosts=['host'], guest=True, prepare=lambda world, ctx: None, steps=[
        ('HOST_ELF', guest_elf, None, guest_launched),
        ('HOST_KILL', guest_kill, None, guest_killed),
        ('GUEST_UPLOAD', guest_upload_host, converge_guest_upload, guest_shipped),
    ]),
    'guest-installed': dict(hosts=['host'], guest=True, exec_fake='report',
                            fixture_outbound=True,
                            fault_steps=['HOST_ELF', 'LIVE_KILL'],
                            exec_hold='3000', prepare=lambda world, ctx: None, steps=[
        ('HOST_ELF', guest_elf_installed, None, guest_installed_settled),
        ('HOST_KILL', guest_kill, None, guest_killed),
        ('LIVE_KILL', guest_live_kill, None, guest_live_killed),
    ]),
    # The rekey itself runs during startup: guest-startup sweeps it
    # (rekey-journals); the fault mode would only repeat the guest flow.
    'guest-rekey': dict(hosts=['host'], guest=True, prepare=lambda world, ctx: None,
                        skip_modes=['fault'],
                        step_env={
        # bhyve restored the VM as 43/100 from 42/99: the guest daemon's
        # identity query reports the rekey once, then the new lifetime
        'REKEY': {'HT_DTT_IDENTITY': '1,43,100,42,99',
                  'HT_DTT_IDENTITY_AFTER': '0,43,100,0,0'},
        'HOST_ELF_2': {'HT_DTT_IDENTITY': '0,43,100,0,0',
                       'HT_DTT_IDENTITY_AFTER': '0,43,100,0,0'},
    }, steps=[
        ('HOST_ELF', guest_elf, None, guest_launched),
        ('HOST_KILL', guest_kill, None, guest_killed),
        ('REKEY', guest_rekeyed_wait, None, guest_rekeyed),
        ('HOST_ELF_2', guest_elf_new_lifetime, None, guest_launched_new),
    ]),
    'fresh-session': dict(hosts=['host'], consumer=True, prepare=prepare_fresh, steps=[
        ('UPLOAD', step_upload_settled(601, b'\xa1', b'\xb1'), None, executed),
        ('SESSION_STOP_1', session_step(MSG_SESSION_STOP), None, consumer_stop_acked),
        ('SESSION_STOP_2', session_step(MSG_SESSION_STOP), None, fresh_stop_done),
        ('SESSION_RELEASE', session_step(MSG_SESSION_RELEASE), None, None),
    ], setup={'SESSION_STOP_1': gate_suspend, 'SESSION_RELEASE': release_setup}),
}


def snapshot(world, directory):
    directory.mkdir(parents=True)
    for name, h in world.hosts.items():
        shutil.copytree(h.root, directory / name, symlinks=True,
                        ignore=shutil.ignore_patterns('sub.sock', 'inject.sock', 'dtraced.pid',
                                                      'stderr.*', 'fault*'))


def reference(flowname):
    flow = FLOWS[flowname]
    base = out / flowname
    if base.exists():
        shutil.rmtree(base)
    base.mkdir()
    world = World(flow)
    ctx = {}
    record = {'steps': []}
    try:
        flow['prepare'](world, ctx)
        for name, run, _, _ in flow['steps']:
            snap = base / ('snap-' + name)
            snapshot(world, snap)
            elog = Path(world.hosts['host'].root) / 'entries.log'
            elog.unlink(missing_ok=True)
            world.hosts['host'].env['HT_ENTRY_LOG'] = str(elog)
            world.start(name)
            if name in flow.get('setup', {}):
                flow['setup'][name](world, ctx)
            attach(world, ctx)
            reply = run(world, ctx)
            time.sleep(0.3)
            exits = world.stop()
            reached = sorted(set(elog.read_text().split())) if elog.exists() else []
            world.hosts['host'].env.pop('HT_ENTRY_LOG', None)
            record['steps'].append({'step': name, 'reply': reply,
                                    'state': canonical(world), 'exits': exits,
                                    'entries': reached})
            if any(exits.values()):
                raise RuntimeError('reference exit %r' % exits)
    finally:
        record['logs_tail'] = world.logs()[-3000:]
        world.close()
    (base / 'reference.json').write_text(json.dumps(record, indent=1, default=str))
    return ctx, record


def one_point(flowname, index, entry, kind, n, ctx, ref):
    flow = FLOWS[flowname]
    name, run, converge, effect = flow['steps'][index]
    snap = out / flowname / ('snap-' + name)
    world = World(flow, copy_from={h: snap / h for h in flow['hosts']}, fault=True)
    result = {'step': name, 'entry': entry, 'kind': kind, 'n': n}
    try:
        world.start(name)
        if name in flow.get('setup', {}):
            flow['setup'][name](world, ctx)
        target = world.hosts['host']
        Path(target.env['HT_FAULT_FILE']).write_text('%s %d %s\n' % (kind, n, entry))
        try:
            attach(world, ctx)
            consumer = getattr(world, 'consumer', None)
            refused_registration = consumer is not None and \
                getattr(consumer, 'registered', b'\x01') != b'\x01'
            first = run(world, ctx)
        except (OSError, EOFError) as exc:
            refused_registration = True
            # the fault refused a peer's admission (e.g. its replay
            # manifest could not be listed): the peer sees the channel close
            first = ['refused: ' + type(exc).__name__]
        time.sleep(0.3)
        fired_file = Path(target.env['HT_FAULT_FILE'] + '.fired')
        fired = fired_file.read_text().strip() if fired_file.exists() else ''
        Path(target.env['HT_FAULT_FILE']).unlink(missing_ok=True)
        result['fired'] = fired
        result['first'] = first
        if not fired and effect is not None:
            wait_until(lambda: effect(world, ctx), 30)
        exits = world.stop()
        if not fired:
            result['ok'] = (first == ref['reply'] and canonical(world) == ref['state']
                            and not any(exits.values()))
            if not result['ok']:
                result['state'] = canonical(world)
            return result
        # converge: new incarnation, reconnected peers, real-peer retries
        world.start(name)
        attach(world, ctx)
        reply = first
        if effect is None:
            # nothing observable proves the step took effect before the
            # fault: the peer repeats its (idempotent) request once
            reply = (converge or run)(world, ctx)
        for _ in range(3):
            # generous under sweep load (12 sanitized daemons in parallel)
            if reply == ref['reply'] and (effect is None or
                                          wait_until(lambda: effect(world, ctx), 25)):
                break
            reply = (converge or run)(world, ctx)
        time.sleep(0.5)
        exits2 = world.stop()
        state = canonical(world)
        result['retry'] = reply
        result['ok'] = (reply == ref['reply'] and state == ref['state'] and
                        not any(exits.values()) and not any(exits2.values()))
        # No duplicate delivery: a resend reuses its recorded delivery ID,
        # so one program never reaches the VM under two tokens.
        tokens = {}
        for program, delivery in getattr(world, 'guest_ledger', []):
            tokens.setdefault(program, set()).add(delivery)
        if any(len(ids) > 1 for ids in tokens.values()):
            result['ok'] = False
            result['duplicate'] = {p.hex(): sorted(ids) for p, ids in tokens.items()}
        # R2 (design): a recovered guest delivery is relaunched only for a
        # waiting dtrace(1) -N consumer (launch report required). The
        # `guest` flow has none, so the token stays pending; the
        # `guest-installed` flow repeats the same points with a consumer
        # and must converge.
        key = 'host:inbound'
        if (flowname == 'guest' and state != ref['state'] and key in state and
                reply == ref['reply']):
            pending = list(state[key])
            if '.delivery.X.X.p' in pending:
                pending.remove('.delivery.X.X.p')
            if sorted(pending) == sorted(ref['state'].get(key, [])) and \
                    all(state.get(k) == v for k, v in ref['state'].items() if k != key):
                result['finding'] = 'R2 replay awaits a registered identifier'
                result['ok'] = not any(exits.values()) and not any(exits2.values())
        if state != ref['state']:
            result['state'] = state
            # R1 (design, not a defect): recipients of a guest upload are
            # fixed when it is accepted (.cohort). When the fault refused
            # the consumer's registration (dtrace(1) exits on that), the
            # upload accepted meanwhile has no recipient, durably: exactly
            # the reference without that upload's consumer records.
            key = 'host:inbound'
            if refused_registration and key in state and key in ref['state']:
                expect = list(ref['state'][key])
                for n in ('.cohort.X.X', '.consumer.X.X.X.N', '.execution.X.X.X',
                          '.handle.X.X.X', '.program.X.X.X'):
                    if n in expect:
                        expect.remove(n)
                if sorted(state[key]) == sorted(expect) and reply == ref['reply'] and \
                        all(state.get(k) == v for k, v in ref['state'].items() if k != key):
                    result['finding'] = 'R1 no recipient (registration refused)'
                    result['ok'] = not any(exits.values()) and not any(exits2.values())
        return result
    except Exception:
        result['ok'] = False
        result['exception'] = traceback.format_exc()[-1500:]
        return result
    finally:
        logs = world.logs()
        bad = [m for m in SANITIZER if m in logs]
        if bad:
            result['ok'] = False
            result['sanitizer'] = logs[max(0, logs.find(bad[0]) - 300):][:2500]
        if globals().get('KEEP_LOGS'):
            result['logs'] = logs[-4000:]
            g = getattr(world, 'guest', None)
            if g is not None:
                result['guest_model'] = {'cleanups': g.cleanups, 'reports': g.reports,
                                         'kills': len(g.kills),
                                         'unacked': len(g.unacked)}
            result['raw'] = {n: sorted(os.listdir(Path(h.root) / 'state' / 'outbound'))
                             for n, h in world.hosts.items()
                             if (Path(h.root) / 'state' / 'outbound').exists()}
            result['guest'] = {'programs': len(world.guest.programs) if hasattr(world, 'guest') else None}
        world.close()


def sweep(flowname):
    flow = FLOWS[flowname]
    ctx, record = reference(flowname)
    results = []
    for index, (name, _, _, _) in enumerate(flow['steps']):
        if steps is not None and name not in steps:
            continue
        if name not in flow.get('fault_steps', [name]):
            continue	# the same step is swept in another flow
        reached = record['steps'][index].get('entries')
        if reached is not None:
            # startup and shutdown run before the step and are swept by
            # the startup modes
            reached = [e for e in reached
                       if e not in ('initialize', 'finalize', 'populate_existing')]
        for entry in [e for e in (entries or reached or []) if reached is None or e in reached]:
            for kind in kinds:
                n, done = 0, False
                while not done:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
                        batch = list(pool.map(lambda k: one_point(
                            flowname, index, entry, kind, k, ctx, record['steps'][index]),
                            range(n, n + jobs)))
                    for r in batch:
                        results.append(r)
                        if not r.get('fired') and 'exception' not in r:
                            done = True
                    n += jobs
                    if n > 800:
                        results.append({'step': name, 'entry': entry, 'kind': kind,
                                        'ok': False, 'error': 'more than 800 points'})
                        break
    return record, results


# ---------------------------------------------------------- corrupt mode
CORRUPTIONS = ('flip-first', 'flip-middle', 'flip-last', 'truncate-half',
               'extend', 'empty', 'mode-0644', 'extra-link', 'directory',
               'symlink')


def corrupt(path, how):
    data = path.read_bytes() if path.is_file() else b''
    if how.startswith('flip') and data:
        at = {'flip-first': 0, 'flip-middle': len(data) // 2,
              'flip-last': len(data) - 1}[how]
        b = bytearray(data)
        b[at] ^= 0x41
        path.write_bytes(bytes(b))
    elif how == 'truncate-half':
        path.write_bytes(data[:len(data) // 2])
    elif how == 'extend':
        path.write_bytes(data + b'\0')
    elif how == 'empty':
        path.write_bytes(b'')
    elif how == 'mode-0644':
        os.chmod(path, 0o644)
    elif how == 'extra-link':
        os.link(path, path.parent / ('corrupt-link-' + path.name[:40]))
    elif how == 'directory':
        path.unlink()
        path.mkdir(mode=0o700)
    elif how == 'symlink':
        path.unlink()
        path.symlink_to('/dev/null')


def one_corruption(flowname, index, rel, how, ctx, ref):
    """A damaged journal or spool never yields a different success: the
    daemon refuses to start, or the step fails, or it returns exactly the
    reference reply; no sanitizer report, clean exits."""
    flow = FLOWS[flowname]
    name, run, _, _ = flow['steps'][index]
    snap = out / flowname / ('snap-' + name)
    world = World(flow, copy_from={h: snap / h for h in flow['hosts']})
    result = {'step': name, 'file': rel, 'how': how}
    try:
        corrupt(Path(world.hosts['host'].root) / 'state' / rel, how)
        if name in flow.get('setup', {}):
            flow['setup'][name](world, ctx)
        try:
            world.start(name)
        except RuntimeError:
            h = world.hosts['host']
            status = h.proc.wait(timeout=20) if h.proc else None
            result['start'] = 'refused (%s)' % status
            result['ok'] = status not in (0, None)
            world.stop()
            return result
        try:
            attach(world, ctx)
            reply = run(world, ctx)
        except (OSError, EOFError) as exc:
            reply = ['eof:' + type(exc).__name__]
        result['reply'] = reply
        exits = world.stop()
        failed = bool(reply) and (reply[0] in ('00', '') or str(reply[0]).startswith('eof'))
        result['ok'] = (failed or reply == ref['reply']) and not any(exits.values())
        result['exits'] = exits
        return result
    except Exception:
        result['ok'] = False
        result['exception'] = traceback.format_exc()[-1500:]
        return result
    finally:
        logs = world.logs()
        bad = [m for m in SANITIZER if m in logs]
        if bad:
            result['ok'] = False
            result['sanitizer'] = logs[max(0, logs.find(bad[0]) - 300):][:2500]
        world.close()


def corrupt_sweep(flowname):
    flow = FLOWS[flowname]
    ctx, record = reference(flowname)
    seen, tasks = set(), []
    for index, (name, _, _, _) in enumerate(flow['steps']):
        state = out / flowname / ('snap-' + name) / 'host' / 'state'
        for path in sorted(state.rglob('*')):
            if not path.is_file() or path.name.endswith('.lock') or \
                    path.name.startswith('.handoff-tmp.'):
                continue
            rel = str(path.relative_to(state))
            key = (re.sub(r'[0-9a-f]{8,}', 'X', rel),
                   hashlib.sha256(path.read_bytes()).hexdigest())
            if key in seen:
                continue
            seen.add(key)
            for how in CORRUPTIONS:
                tasks.append((index, rel, how))
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        results = list(pool.map(lambda t: one_corruption(
            flowname, t[0], t[1], t[2], ctx, record['steps'][t[0]]), tasks))
    return record, results


# ---------------------------------------------------------- hostile mode
# Header layout (dtraced_wire_encode_header): (offset, size) per field.
FIELDS = {'type': (0, 8), 'len': (8, 8), 'delivery': (16, 8), 'program': (24, 16),
          'source': (40, 16), 'ident_present': (56, 4), 'filter': (60, 4),
          'vmid': (64, 2), 'epoch': (72, 8), 'location': (80, 64), 'ident': (144, 128),
          'kill.pid': (272, 4), 'kill.vmid': (276, 2), 'kill.epoch': (280, 8),
          'kill.source': (288, 16), 'cleanup.num': (304, 8), 'cleanup.vmid': (312, 2),
          'cleanup.epoch': (320, 8), 'info.count': (328, 8),
          'installed.delivery': (336, 8), 'installed.vmid': (344, 2),
          'installed.epoch': (352, 8), 'installed.program': (360, 16),
          'installed.source': (376, 16), 'installed.name': (392, 128)}


def mutations(head, body):
    """Single-field header mutations and body damage of one valid frame."""
    yield 'original', bytes(head), body
    for name, (off, size) in FIELDS.items():
        if name == 'type':
            continue
        for how in ('zero', 'ones', 'flip', 'bump'):
            h = bytearray(head)
            if how == 'zero':
                h[off:off + size] = bytes(size)
            elif how == 'ones':
                h[off:off + size] = b'\xff' * size
            elif how == 'flip':
                h[off] ^= 0x01
            else:
                h[off + size - 1] = (h[off + size - 1] + 1) & 0xff
            if bytes(h) != bytes(head):
                yield '%s:%s' % (name, how), bytes(h), body
    if body:
        yield 'body:truncate', bytes(head), body[:-1]
        yield 'body:extend', bytes(head), body + b'\0'
        for at in sorted({0, len(body) // 2, len(body) - 1}):
            b = bytearray(body)
            b[at] ^= 0x41
            yield 'body:flip@%d' % at, bytes(head), bytes(b)


def tree_digest(world):
    h = hashlib.sha256()
    root = Path(world.hosts['host'].root) / 'state'
    for path in sorted(root.rglob('*')):
        if path.name.startswith(('.handoff-tmp.', '.elf.')) or path.name.endswith('.lock'):
            continue
        h.update(str(path.relative_to(root)).encode())
        try:
            st = path.lstat()
            h.update(b'%o:%d' % (st.st_mode, st.st_nlink))
            if path.is_file() and not path.is_symlink():
                h.update(path.read_bytes())
        except OSError:
            h.update(b'?')
    return h.hexdigest()


def templates(world, ctx, flowname, step):
    t = []
    if FLOWS[flowname].get('guest'):
        body = b'\x7fELF' + b'guest-linked' * 8
        t.append(('control', bytes(elf_frame(len(body), b'\xc9')), body))
        t.append(('control', bytes(elf_frame(len(body), b'\xc9', b'inbound', b'\xd9')), body))
        return t
    vm = world.vms['S']
    if flowname == 'outbound-delivery' and 'delivery' in ctx:
        delivery, program, source, _ = ctx['delivery']
        for kind in (MSG_INSTALLED, MSG_UNINSTALLED, MSG_STATUS):
            t.append(('forwarder', bytes(observation(kind, delivery, vm, program, source)), b''))
        h = header(MSG_KILL_APPLIED)
        struct.pack_into('<IHxxQ', h, 272, 4242, 7, 9)
        h[288:304] = b'\x51'.ljust(16, b'\0')
        t.append(('forwarder', bytes(h), b''))
    if flowname == 'outbound-delivery':
        t.append(('control', bytes(elf_frame(len(ctx['elf']), b'\x51')), ctx['elf']))
        t.append(('control', bytes(kill_frame(4242, vm, b'\x51')), b''))
        ch, cb = cleanup_frame(['guest-a'])
        t.append(('control', bytes(ch), cb))
        a = header(MSG_CLEANUP_APPLIED)
        struct.pack_into('<H', a, 312, 7)
        struct.pack_into('<QQ', a, 320, 9, 1)
        t.append(('forwarder', bytes(a), b''))
    if flowname in ('host-ingest', 'fresh-session'):
        name = vm.name.encode()
        elf = b'\x7fELF' + b'\xa9' * 8
        body = struct.pack('<IHHQQ', 0x32565448, 2, 7, 9, len(name)) + name + elf
        t.append(('forwarder', bytes(elf_frame(len(body), b'\xb9', b'inbound', b'\xa9', 609)), body))
        st = header(MSG_INGRESS_STATUS if 'MSG_INGRESS_STATUS' in globals() else 8)
        st = bytes(observation(8, 601, vm, b'\xa1'.ljust(16, b'\0'), b'\xb1'.ljust(16, b'\0')))
        t.append(('forwarder', st, b''))
        ack = struct.pack('<Q16s16sHBxxxxxQ', 601, b'\xa1', b'\xb1', 7, 1, 9)
        t.append(('reporter', bytes(header(MSG_CONSUMER_EXECUTION, 72)),
                  ack + b'\x42'.ljust(16, b'\0')))
        t.append(('registrar', bytes(header(MSG_CONSUMER_PROGRAM, 32)),
                  hashlib.sha256(b'compiled program').digest()))
    if flowname == 'derived':
        # a derived publication for the accepted upload 601 (parent identity
        # in the installed slot, HDERIV1 program ID, target envelope)
        session = b'\xc1'.ljust(16, b'\0')
        program, source = b'\xa1'.ljust(16, b'\0'), b'\xb1'.ljust(16, b'\0')
        payload = struct.pack('<IHHQQ', 0x32544748, 2, 7, 9, 0) + b'\x7fELF' + b'mutant' * 6
        pre = b'HDERIV1\0' + session + struct.pack('<QHQ', 601, 7, 9) + program + \
            source + hashlib.sha256(payload).digest()
        h = header(MSG_ELF, len(payload))
        h[24:40] = hashlib.sha256(pre).digest()[:16]
        h[40:56] = source
        h[80:88] = b'outbound'
        struct.pack_into('<QHxxxxxxQ', h, 336, 601, 7, 9)
        h[360:376] = program
        h[376:392] = source
        h[392:408] = session
        t.append(('reporter', bytes(h), payload))
        ack = struct.pack('<Q16s16sHBxxxxxQ', 601, b'\xa1', b'\xb1', 7, 2, 9)
        t.append(('reporter', bytes(header(MSG_CONSUMER_EXECUTION, 72)),
                  ack + b'\x42'.ljust(16, b'\0')))
    if flowname == 'fresh-session':
        for kind, magic in ((MSG_SESSION_STOP, b'FST1'), (MSG_SESSION_RELEASE, b'FRE1')):
            t.append(('forwarder', bytes(header(kind, 24)), magic + bytes(4) + ctx['stop_token']))
        proof = b'HSA1' + bytes(4) + ctx['stop_token'] + b'\x42'.ljust(16, b'\0') + \
            b'\xc1'.ljust(16, b'\0') + hashlib.sha256(b'compiled program').digest() + \
            struct.pack('<HxxxxxxQ', 7, 9) + b'\x01' + bytes(7)
        t.append(('reporter', bytes(header(MSG_CONSUMER_STOP_COMMIT, len(proof))), proof))
    # Crafted trace-continuity (HANDOFF) input against a daemon that holds
    # live journals: HT-C is a disabled feature, but its request decoders
    # and handlers stay reachable by any attested forwarder and must refuse
    # unexpected input without touching durable state.
    token = hashlib.sha256(b'crafted handoff').digest()[:16]
    digest = hashlib.sha256(b'crafted checkpoint').digest()
    for op in (1, 2, 4, 7, 9, 12, 15, 16, 18, 19, 22, 26, 28, 29):
        t.append(('forwarder', bytes(header(MSG_HANDOFF, 49)),
                  bytes([op]) + token + (bytes(32) if op in (12, 16) else digest)))
    t.append(('forwarder', bytes(header(MSG_HANDOFF_IMPORT, 48 + 96)),
              token + digest + b'HTX1' + bytes(60) + hashlib.sha256(b'x').digest()))
    t.append(('forwarder', bytes(header(MSG_HANDOFF_RELEASE_IMPORT, 48 + 324)),
              token + digest + b'HSA1\x01' + bytes(319)))
    t.append(('forwarder', bytes(header(MSG_HANDOFF_DELIVERY, 96)),
              delivery_wire(token, digest, 77, b'\x01', b'\x02')))
    t.append(('forwarder', bytes(header(MSG_HANDOFF_BIND_DELIVERY, 128)),
              delivery_wire(token, digest, 77, b'\x01', b'\x02', 0, digest)))
    t.append(('forwarder', bytes(header(MSG_HANDOFF_KILL, 72)),
              kill_wire(token, digest, 4242, b'\x51')))
    t.append(('forwarder', bytes(header(MSG_HANDOFF_BIND_KILL, 72)),
              kill_wire(token, digest, 4242, b'\x51')))
    t.append(('forwarder', bytes(header(MSG_HANDOFF_CLEANUP, 56)),
              token + digest + struct.pack('<Q', 1)))
    return t


def channel(world, ctx, kind):
    host = world.hosts['host']
    if kind == 'forwarder':
        return world.vms['S'].channel()
    if kind == 'control':
        return control(host)
    s = host.connect()
    if kind == 'reporter':
        s.sendall(hello(KIND_CONSUMER, SUB_READDATA, ctx.get('ident', 'dtrace-1-x'),
                        b'\xc1'))
    else:			# a second registration attempt from the same identity
        s.sendall(hello(KIND_CONSUMER, SUB_READDATA | SUB_ELFWRITE,
                        ctx.get('ident', 'dtrace-1-x'), b'\xc2'))
    return s


def hostile_step(flowname, index, ctx):
    flow = FLOWS[flowname]
    name = flow['steps'][index][0]
    snap = out / flowname / ('snap-' + name)
    world = World(flow, copy_from={h: snap / h for h in flow['hosts']})
    results = []
    try:
        if name in flow.get('setup', {}):
            flow['setup'][name](world, ctx)
        world.start(name)
        attach(world, ctx)
        for kind, head, body in templates(world, ctx, flowname, name):
            for label, h, b in mutations(head, body):
                before = tree_digest(world)
                try:
                    s = channel(world, ctx, kind)
                    s.settimeout(5)
                    s.sendall(struct.pack('<Q', len(h) + len(b)) + h + b)
                    ack = s.recv(1).hex() or 'eof'
                    s.close()
                except (OSError, EOFError) as exc:
                    ack = 'eof:' + type(exc).__name__
                time.sleep(0.05)
                after = tree_digest(world)
                ok = ack == '01' or before == after
                results.append({'step': name, 'template': kind + ':%d' %
                                struct.unpack_from('<Q', head, 0)[0],
                                'mutation': label, 'ack': ack, 'ok': ok})
        exits = world.stop()
        if any(exits.values()):
            results.append({'step': name, 'ok': False, 'exits': exits})
    except Exception:
        results.append({'step': name, 'ok': False,
                        'exception': traceback.format_exc()[-1500:]})
    finally:
        logs = world.logs()
        bad = [m for m in SANITIZER if m in logs]
        if bad:
            results.append({'step': name, 'ok': False,
                            'sanitizer': logs[max(0, logs.find(bad[0]) - 300):][:2500]})
        world.close()
    return results


def hostile_sweep(flowname):
    flow = FLOWS[flowname]
    ctx, record = reference(flowname)
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        parts = list(pool.map(lambda i: hostile_step(flowname, i, ctx),
                              range(len(flow['steps']))))
    return record, [r for part in parts for r in part]


# ---------------------------------------------------------- startup mode
_clean_state = {}
_clean_lock = threading.Lock()


def clean_restart_state(flowname, index):
    """Canonical state after one fault-free start and stop on a copy."""
    key = (flowname, index)
    with _clean_lock:
        if key in _clean_state:
            return _clean_state[key]
        flow = FLOWS[flowname]
        snap = out / flowname / ('snap-' + flow['steps'][index][0])
        w = World(flow, copy_from={h: snap / h for h in flow['hosts']})
        try:
            w.start(flow['steps'][index][0])
            w.stop()
            _clean_state[key] = canonical(w)
        finally:
            w.close()
        return _clean_state[key]


def one_startup(flowname, index, entry, kind, n):
    """N-th failure inside daemon startup (initialize) or shutdown
    (finalize) on a snapshot's journals: the incarnation either starts and
    serves, or refuses cleanly (nonzero exit, no socket); in both cases the
    next clean incarnation starts, serves a statistics request and keeps the
    journal state exactly (canonical state unchanged); no sanitizer report."""
    flow = FLOWS[flowname]
    name = flow['steps'][index][0]
    snap = out / flowname / ('snap-' + name)
    world = World(flow, copy_from={h: snap / h for h in flow['hosts']}, fault=True)
    result = {'step': name, 'entry': entry, 'kind': kind, 'n': n}
    try:
        h = world.hosts['host']
        before = clean_restart_state(flowname, index)
        world.step_env(name)
        h.start_timeout = 20
        Path(h.env['HT_FAULT_FILE']).write_text('%s %d %s\n' % (kind, n, entry))
        try:
            h.start()
            started = True
        except RuntimeError:
            started = False
        status = h.stop()
        fired_file = Path(h.env['HT_FAULT_FILE'] + '.fired')
        result['fired'] = fired_file.read_text().strip() if fired_file.exists() else ''
        Path(h.env['HT_FAULT_FILE']).unlink(missing_ok=True)
        result['started'] = started
        result['status'] = status
        clean_refusal = (not started and status not in (0, None))
        h.env.pop('HT_FAULT_FILE', None)
        h.start()
        c = control(h)
        frame(c, header(15))
        stats_ack = c.recv(1).hex()
        c.close()
        status2 = h.stop()
        after = canonical(world)
        result['stats'] = stats_ack
        # a failed shutdown step is reported through the exit status
        result['ok'] = ((started and (status == 0 or entry == 'finalize')) or
                        clean_refusal) and \
            status2 == 0 and stats_ack == '01' and after == before
        if after != before:
            result['before'], result['after'] = before, after
        return result
    except Exception:
        result['ok'] = False
        result['exception'] = traceback.format_exc()[-1500:]
        return result
    finally:
        logs = world.logs()
        bad = [m for m in SANITIZER if m in logs]
        if bad:
            result['ok'] = False
            result['sanitizer'] = logs[max(0, logs.find(bad[0]) - 300):][:2500]
        world.close()


def startup_sweep(flowname):
    flow = FLOWS[flowname]
    ctx, record = reference(flowname)
    results = []
    # the last snapshot holds the richest journal state of the flow
    for index in (len(flow['steps']) - 1,):
        for entry in ('initialize', 'finalize'):
            for kind in kinds:
                n, done = 0, False
                while not done:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
                        batch = list(pool.map(lambda k: one_startup(
                            flowname, index, entry, kind, k), range(n, n + jobs)))
                    for r in batch:
                        results.append(r)
                        if not r.get('fired') and 'exception' not in r:
                            done = True
                    n += jobs
                    if n > 2000:
                        break
    return record, results


# ----------------------------------------------------- guest-startup mode
# Guest (minion, -m) daemons on the scripted transport of the daemon-main
# shim: identity "flags,vmid,epoch,old_vmid,old_epoch" and cleanup state
# "flags,delivery,vmid,epoch,reserved" as the guest kernel reports them.
GUEST_CASES = {
    'clean': dict(HT_DTT_IDENTITY='0,42,99,0,0'),
    'rekey-empty': dict(HT_DTT_IDENTITY='1,43,100,42,99',
                        HT_DTT_IDENTITY_AFTER='0,43,100,0,0'),
    'fresh-session': dict(HT_DTT_IDENTITY='4,43,100,42,99',
                          HT_DTT_CLEANUP='7,8,42,99,0',
                          HT_DTT_IDENTITY_AFTER='16,43,100,42,99',
                          HT_DTT_CLEANUP_AFTER='0,0,0,0,0'),
    'cleanup-applied': dict(HT_DTT_IDENTITY='0,42,99,0,0',
                            HT_DTT_CLEANUP='1,8,42,99,0', marker='1'),
    # the guest flow's journals (an exited delivery, an applied KILL and a
    # shipped upload) restarted after the VM was rekeyed to 43/100
    'rekey-journals': dict(HT_DTT_IDENTITY='1,43,100,42,99',
                           HT_DTT_IDENTITY_AFTER='0,43,100,0,0',
                           snapshot=('guest', 'GUEST_UPLOAD')),
    'same-identity-journals': dict(HT_DTT_IDENTITY='0,42,99,0,0',
                                   snapshot=('guest', 'GUEST_UPLOAD')),
}


_guest_snapshot_lock = threading.Lock()


def guest_daemon(case, fault):
    env = {k: v for k, v in GUEST_CASES[case].items() if k not in ('marker', 'snapshot')}
    env['HT_DTT_ANSWER'] = '1'
    env['HT_DTT_ACK'] = '1'
    env['HT_PD_BIRTH'] = '1'
    snap = GUEST_CASES[case].get('snapshot')
    source = None
    if snap is not None:
        flowname, step = snap
        with _guest_snapshot_lock:   # parallel cases share one reference run
            if not (out / flowname / ('snap-' + step)).exists():
                reference(flowname)
        source = out / flowname / ('snap-' + step) / 'host'
    h = Daemon('guest', ['-m'], env=env, copy_from=source)
    # startup sweeps: a fault either refuses promptly or leaves a start that
    # never completes; do not spend the long load allowance on the latter
    h.start_timeout = 15
    state = Path(h.root) / 'state'
    for d in ('', 'inbound', 'outbound'):
        (state / d).mkdir(mode=0o700, exist_ok=True)
    if GUEST_CASES[case].get('marker'):
        os.close(os.open(state / 'inbound' / '.child-ledger-v1',
                         os.O_CREAT | os.O_WRONLY, 0o600))
    if fault:
        h.env['HT_FAULT_FILE'] = os.path.join(h.root, 'fault')
    return h


def guest_tree(h):
    out_ = {}
    root = Path(h.root) / 'state'
    for p in sorted(root.rglob('*')):
        if p.name.endswith('.lock') or p.name.startswith(('.handoff-tmp.', '.elf.')):
            continue
        out_[str(p.relative_to(root))] = 'dir' if p.is_dir() else \
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else 'other'
    return out_


_guest_clean = {}


def guest_reference(case):
    if case not in _guest_clean:
        h = guest_daemon(case, False)
        try:
            h.start()
            h.stop()
            _guest_clean[case] = guest_tree(h)
        finally:
            h.close()
    return _guest_clean[case]


def one_guest_startup(case, entry, kind, n):
    """N-th failure inside guest startup (initialize) or shutdown
    (finalize): the guest starts or refuses cleanly (or re-executes, exit
    73, which the shim emulates); a following clean incarnation reaches the
    same journal tree as an undisturbed start; no sanitizer report."""
    result = {'case': case, 'entry': entry, 'kind': kind, 'n': n}
    h = guest_daemon(case, True)
    try:
        Path(h.env['HT_FAULT_FILE']).write_text('%s %d %s\n' % (kind, n, entry))
        try:
            h.start()
            started = True
        except RuntimeError:
            started = False
        status = h.stop()
        fired_file = Path(h.env['HT_FAULT_FILE'] + '.fired')
        result['fired'] = fired_file.read_text().strip() if fired_file.exists() else ''
        Path(h.env['HT_FAULT_FILE']).unlink(missing_ok=True)
        result['started'], result['status'] = started, status
        h.env.pop('HT_FAULT_FILE', None)
        try:
            h.start()
            restarted = True
        except RuntimeError:
            restarted = False
        status2 = h.stop()
        tree = guest_tree(h)
        expected = guest_reference(case)
        result['ok'] = (((started and (status == 0 or entry == 'finalize')) or
                         (not started and status not in (0, None)))
                        and restarted and status2 == 0 and tree == expected)
        if tree != expected:
            result['tree_diff'] = sorted(set(tree.items()) ^ set(expected.items()))[:10]
        return result
    except Exception:
        result['ok'] = False
        result['exception'] = traceback.format_exc()[-1500:]
        return result
    finally:
        logs = '\n'.join(h.logs)
        bad = [m for m in SANITIZER if m in logs]
        if bad:
            result['ok'] = False
            result['sanitizer'] = logs[max(0, logs.find(bad[0]) - 300):][:2500]
        h.close()


def guest_startup_sweep(_flowname):
    results = []
    for case in GUEST_CASES:
        for entry in ('initialize', 'finalize'):
            for kind in kinds:
                # Allocation failures: the first 200 allocations each, then
                # every 5th (a guest start makes a few thousand); every
                # file-system call and thread creation is swept.
                n, done = 0, False
                while not done:
                    stride = 5 if kind == 'oom' and n >= 200 else 1
                    points = list(range(n, n + jobs * stride, stride))
                    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
                        batch = list(pool.map(lambda k: one_guest_startup(
                            case, entry, kind, k), points))
                    for r in batch:
                        results.append(r)
                        if not r.get('fired') and 'exception' not in r:
                            done = True
                    n = points[-1] + stride
                    if n > 4000:
                        break
    (out / 'guest-startup').mkdir(exist_ok=True)
    return {'steps': [{} for _ in GUEST_CASES]}, results


# -------------------------------------------------------- callfault mode
CALLS = ('kqueue', 'kevent', 'listen', 'socket', 'accept4', 'fcntl', 'pdwait',
         'pdkill', 'pdfork', 'pipe2', 'socketpair', 'setsockopt', 'poll',
         'send', 'recv', 'recvmsg', 'shutdown', 'getsockopt')


def one_callfault(flowname, index, call, n):
    """The n-th call of a system function, in any daemon thread (listener,
    directory watchers, admission, workers), fails once while an
    incarnation starts, admits the flow's peers and serves statistics. The
    daemon keeps serving or shuts down without a sanitizer report; the next
    clean incarnation starts, serves statistics and leaves the journal
    state exactly as an undisturbed restart does."""
    flow = FLOWS[flowname]
    name = flow['steps'][index][0]
    snap = out / flowname / ('snap-' + name)
    world = World(flow, copy_from={h: snap / h for h in flow['hosts']}, fault=True)
    ctx = CALL_CTX[flowname]
    result = {'step': name, 'call': call, 'n': n}
    try:
        h = world.hosts['host']
        before = clean_restart_state(flowname, index)
        world.step_env(name)
        h.start_timeout = 20
        h.env['HT_CALL_FAULT'] = '%s:%d' % (call, n)
        try:
            h.start()
            started = True
        except RuntimeError:
            started = False
        if started:
            try:
                attach(world, ctx)
                if not flow.get('guest'):
                    c = control(h)
                    frame(c, header(15))
                    c.recv(1)
                    c.close()
                else:
                    time.sleep(0.5)
            except (OSError, EOFError):
                pass
        status = world.stop()['host']
        fired_file = Path(h.env['HT_FAULT_FILE'] + '.fired')
        result['fired'] = fired_file.read_text().strip() if fired_file.exists() else ''
        result['started'], result['status'] = started, status
        h.env.pop('HT_CALL_FAULT', None)
        h.env.pop('HT_FAULT_FILE', None)
        h.start()
        if flow.get('guest'):
            stats_ack = '01'	# guests serve no statistics; started is enough
        else:
            c = control(h)
            frame(c, header(15))
            stats_ack = c.recv(1).hex()
            c.close()
        status2 = h.stop()
        after = canonical(world)
        result['ok'] = status2 == 0 and stats_ack == '01' and after == before and \
            status is not None
        if after != before:
            result['before'], result['after'] = before, after
        return result
    except Exception:
        result['ok'] = False
        result['exception'] = traceback.format_exc()[-1500:]
        return result
    finally:
        logs = world.logs()
        bad = [m for m in SANITIZER if m in logs]
        if bad:
            result['ok'] = False
            result['sanitizer'] = logs[max(0, logs.find(bad[0]) - 300):][:2500]
        world.close()


CALL_CTX = {}


def callfault_sweep(flowname):
    flow = FLOWS[flowname]
    ctx, record = reference(flowname)
    CALL_CTX[flowname] = ctx
    index = len(flow['steps']) - 1
    results = []
    for call in CALLS:
        n, done = 1, False
        while not done:
            with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
                batch = list(pool.map(lambda k: one_callfault(flowname, index, call, k),
                                      range(n, n + jobs)))
            for r in batch:
                results.append(r)
                if not r.get('fired') and 'exception' not in r:
                    done = True
            n += jobs
            if n > 120:
                break
    return record, results


if point is not None:
    # debugging aid: one injected point with the daemon logs
    flowname, stepname, entry, kind, n = point
    ctx, rec = reference(flowname)
    index = [s_[0] for s_ in FLOWS[flowname]['steps']].index(stepname)
    KEEP_LOGS = True
    r = one_point(flowname, index, entry, kind, int(n), ctx, rec['steps'][index])
    print(json.dumps(r, indent=1, default=str)[:6000])
    raise SystemExit(0)

if reference_only:
    for flowname in (selected or list(FLOWS)):
        ctx, rec = reference(flowname)
        print(flowname, json.dumps([(s['step'], s['reply'], s['exits'])
                                    for s in rec['steps']]))
        print('  final state', json.dumps(rec['steps'][-1]['state'])[:1500])
    raise SystemExit(0)

summary = {}
# The host startup mode serves statistics from a control machine; the guest
# daemon's startup is the guest-startup mode.
for flowname in (selected or (['guest-startup'] if mode == 'guest-startup'
                              else [f for f in FLOWS if not (
                                  mode == 'startup' and FLOWS[f].get('guest')) and
                                  mode not in FLOWS[f].get('skip_modes', [])])):
    started = time.monotonic()
    record, results = {'fault': sweep, 'corrupt': corrupt_sweep,
                       'hostile': hostile_sweep, 'startup': startup_sweep,
                       'guest-startup': guest_startup_sweep,
                       'callfault': callfault_sweep}[mode](flowname)
    points = [r for r in results if r.get('fired') or mode != 'fault']
    failed = [r for r in results if not r.get('ok')]
    findings = {}
    for r in results:
        if r.get('finding'):
            findings[r['finding']] = findings.get(r['finding'], 0) + 1
    (out / flowname / ('points-%s.json' % mode)).write_text(json.dumps(results, indent=1, default=str))
    summary[flowname] = {'steps': len(record['steps']), 'points': len(points),
                         'failures': len(failed), 'findings': findings,
                         'seconds': round(time.monotonic() - started)}
    for r in failed[:8]:
        print(json.dumps(r, default=str)[:1500])
    print(flowname, json.dumps(summary[flowname]), flush=True)
(out / 'summary.json').write_text(json.dumps(summary, indent=1))
bad = sum(v['failures'] for v in summary.values())
print('live-sweep', mode + ':', json.dumps(summary), 'FAIL' if bad else 'PASS')
raise SystemExit(1 if bad else 0)
