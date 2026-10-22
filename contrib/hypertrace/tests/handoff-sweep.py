#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Fault sweeps over HyperTrace handoff steps in real dtraced incarnations.

Usage: handoff-sweep.py BINARY OUTPUT [FLOW ...] [--mode fault|corrupt|refuse]
                        [--kinds sys,oom] [--jobs N]

BINARY is the daemon-main test executable (actual dtraced objects plus the
daemon-main.cc shim). A flow is a sequence of single-request protocol steps
spoken by emulated bhyve peers (see handoff-peers.py, whose helpers are
reused). The reference run records, before each step, a snapshot of every
host's journals and emulated kernel state, and the step's reply.

For each step and each N, a fresh daemon incarnation is started on a copy of
that snapshot and the step's request runs with exactly one injected failure
(HT_FAULT_FILE): the N-th file-system call ("sys") or the N-th allocation
("oom") made by the thread handling that request. N grows until the request
completes without reaching N.

Modes:
  fault    (default) one injected failure per request, described below.
  corrupt  every journal and spool file present in a snapshot is damaged in
           turn (byte flips, truncation, extension, emptied, group/other
           permissions, a second hard link, replaced by a directory or a
           symlink); a new incarnation then serves the step. Oracle: no
           sanitizer report; the daemon either refuses to start (fail
           closed, exit status nonzero, no socket) or runs and exits 0, and
           the step either fails (NAK/EOF) or returns exactly the reference
           reply - a damaged journal never yields a different success.
  refuse   in each snapshot every handoff operation is sent by every VM
           (source, destination, a replacement and an unrelated VM) with the
           checkpoint digest, the transfer digest and an unrelated digest.
           Oracle: no sanitizer report, exit 0, and every refused request
           (NAK/EOF) leaves the journal trees byte-for-byte unchanged.

Oracles for every injected fault point:
  * no sanitizer report and every incarnation exits 0;
  * the daemon restarts on the same journals (a failed operation never leaves
    state that a new incarnation cannot read);
  * an exact retry of the step then returns exactly the reference reply,
    the post-step status query returns exactly the reference status, and the
    next step of the flow (if any) also returns its reference reply;
  * when the fault never fired, the reply equals the reference reply.
"""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import sys
import tempfile
import time
import traceback

args = [a for a in sys.argv[1:]]
kinds, jobs = ['sys', 'oom'], max(2, (os.cpu_count() or 4) // 2)
mode = 'fault'
if '--mode' in args:
    i = args.index('--mode')
    mode = args[i + 1]
    del args[i:i + 2]
assert mode in ('fault', 'corrupt', 'refuse')
if '--kinds' in args:
    i = args.index('--kinds')
    kinds = args[i + 1].split(',')
    del args[i:i + 2]
if '--jobs' in args:
    i = args.index('--jobs')
    jobs = int(args[i + 1])
    del args[i:i + 2]
binary, out = Path(args[0]).resolve(), Path(args[1]).resolve()
selected = args[2:]
assert binary.is_relative_to('/usr/obj') and out.is_relative_to('/usr/obj')
out.mkdir(parents=True, exist_ok=True)

# Protocol helpers shared with handoff-peers.py.
sys.path.insert(0, str(Path(__file__).resolve().parent))
_binary, _out = binary, out
import htpeerlib
from htpeerlib import *
binary, out = _binary, _out
htpeerlib.binary = binary

SANITIZER = ('AddressSanitizer', 'runtime error:', 'LeakSanitizer',
             'UndefinedBehaviorSanitizer')


class World:
    """Hosts and VMs of one flow instance (reference or snapshot copy)."""

    def __init__(self, flow, copy_from=None, fault=False):
        self.flow = flow
        self.hosts, self.vms, self.extra = {}, {}, {}
        for name, keyed in flow['hosts']:
            env = {}
            if fault:
                env['HT_FAULT_FILE'] = '@FAULT@'
            source = None if copy_from is None else copy_from[name]
            extra = []
            if keyed:
                extra = ['-K', '@ROOT@/keys/own.pem', '-P', '@ROOT@/keys/peer.pub']
            h = Daemon(name, [], copy_from=source, env=env)
            h.extra = [a.replace('@ROOT@', h.root) for a in extra]
            if fault:
                h.env['HT_FAULT_FILE'] = os.path.join(h.root, 'fault')
            self.hosts[name] = h

    def start(self):
        for h in self.hosts.values():
            h.start()

    def stop(self):
        status = {}
        for name, h in self.hosts.items():
            status[name] = h.stop()
        return status

    def close(self):
        for h in self.hosts.values():
            h.close()

    def logs(self):
        return '\n'.join('\n'.join(h.logs) for h in self.hosts.values())


def vm(world, name):
    v = world.vms.get(name)
    return v


# ---------------------------------------------------------------- flows
def setup_keys(world):
    """Two hosts with each other's pinned Ed25519 release keys."""
    names = [n for n, keyed in world.flow['hosts'] if keyed]
    pairs = {}
    for name in names:
        kd = Path(world.hosts[name].root) / 'keys'
        kd.mkdir(mode=0o700, exist_ok=True)
        pairs[name] = make_keys(kd, 'own')
    for name in names:
        other = [n for n in names if n != name]
        peer_pub = pairs[other[0]][1] if other else pairs[name][1]
        shutil.copy(peer_pub, Path(world.hosts[name].root) / 'keys' / 'peer.pub')
    return pairs


def handoff_step(vmname, op, digest_key=None, reply=None):
    def run(world, ctx):
        v = world.vms[vmname]
        digest = ctx[digest_key] if digest_key else ZERO32
        ack, payload = v.handoff(op, ctx['token'], digest, reply=reply)
        if reply == 'status' and payload is not None:
            payload = {k: (v_.hex() if isinstance(v_, bytes) else v_)
                       for k, v_ in payload.items()}
        if reply == 'transfer' and payload is not None:
            payload = hashlib.sha256(payload).hexdigest()
        return [ack, payload]
    return run


def status_query(vmname, kind):
    """Read-only phase query: SOURCE_STATUS or DESTINATION_STATUS."""
    def run(world, ctx):
        v = world.vms[vmname]
        if kind == 'source':
            ack, st = v.handoff('SOURCE_STATUS', ctx['token'], reply='status')
        else:
            ack, st = v.handoff('DESTINATION_STATUS', ctx['token'],
                                ctx['checkpoint'], reply='status')
        return [ack, None if st is None else [st['phase'], st['digest'].hex()]]
    return run


def release_step(world, ctx):
    src = world.vms['S']
    if not src.path.exists():
        # an exact retry: the emulated kernel briefly shows the same VMM
        # lifetime again so a release channel can be authenticated
        src = world.vms['S'] = VM(src.host, src.vmid, src.epoch, src.name,
                                  src.session)
    rel = src.channel(SUB_SOURCE_RELEASE | SUB_ADMISSION_ACK)
    try:
        admitted = recv_exact(rel, 1).hex()
        if src.path.exists():
            src.destroy()
        frame(rel, header(MSG_HANDOFF),
              bytes([OPS['SOURCE_RELEASE']]) + ctx['token'] + ctx['checkpoint'])
        ack = rel.recv(1).hex()
        mode = rel.recv(1).hex() if ack == '01' else None
        body = None
        if mode == '01':
            body = hashlib.sha256(recv_exact(rel, 324)).hexdigest()
        return [admitted, ack, mode, body]
    finally:
        rel.close()


def import_step(world, ctx):
    s = world.vms['D'].channel()
    try:
        frame(s, header(MSG_HANDOFF_IMPORT),
              ctx['token'] + ctx['checkpoint'] + ctx['bundle'])
        return [s.recv(1).hex()]
    finally:
        s.close()


def release_import_step(world, ctx):
    ack, _ = request(world.vms['D'], MSG_HANDOFF_RELEASE_IMPORT,
                     ctx['token'] + ctx['checkpoint'] + ctx['release'],
                     status=False)
    return [ack]


def bind_delivery_step(index):
    def run(world, ctx):
        dl = ctx['deliveries'][index]
        ack, st = request(world.vms['D'], MSG_HANDOFF_BIND_DELIVERY, delivery_wire(
            ctx['token'], ctx['checkpoint'], dl['id'], dl['program'], dl['source'],
            0, dl['digest']))
        return [ack, None if st is None else [st['phase'], st['digest'].hex()]]
    return run


def kill_query_step(bind):
    def run(world, ctx):
        ack, st = request(world.vms['D'],
                          MSG_HANDOFF_BIND_KILL if bind else MSG_HANDOFF_KILL,
                          kill_wire(ctx['token'], ctx['checkpoint'], 4242, b'\x53'))
        return [ack, None if st is None else [st['phase'], st['revoked']]]
    return run


def delivery_query_step(index):
    def run(world, ctx):
        dl = ctx['deliveries'][index]
        ack, st = request(world.vms['D'], MSG_HANDOFF_DELIVERY, delivery_wire(
            ctx['token'], ctx['checkpoint'], dl['id'], dl['program'], dl['source']))
        return [ack, None if st is None else [st['phase'], st['revoked'],
                                              st['digest'].hex()]]
    return run


def make_vm(world, name, hostname, vmid, epoch, session):
    world.vms[name] = VM(world.hosts[hostname], vmid, epoch, 'guest-a', session)


def prepare_same_host(world, ctx):
    make_vm(world, 'S', 'host', 7, 9, b'\x42')
    ctx['token'] = hashlib.sha256(b'sweep-token').digest()[:16]
    ctx['checkpoint'] = hashlib.sha256(b'sweep-checkpoint').digest()


def same_host_export(world, ctx):
    ack, bundle = world.vms['S'].handoff('EXPORT', ctx['token'], reply='transfer')
    if bundle is None:
        return [ack, None]
    ctx.setdefault('xd', bundle[-32:])
    return [ack, hashlib.sha256(bundle).hexdigest()]


def add_destination(world, ctx):
    if 'D' not in world.vms:
        make_vm(world, 'D', world.flow['destination_host'], 8, 10, b'\x43')


def drain_all(world, ctx):
    while True:
        ack, more = world.vms['S'].handoff('SOURCE_DRAIN_STEP', ctx['token'],
                                           ctx['xd'], reply='step')
        if ack != '01' or more == 0:
            return [ack, more]


S_STATUS = status_query('S', 'source')
D_STATUS = status_query('D', 'destination')

FLOWS = {}
FLOWS['same-host'] = dict(
    hosts=[('host', False)], destination_host='host', prepare=prepare_same_host,
    steps=[
        ('GATE_BEGIN', handoff_step('S', 'SOURCE_GATE_BEGIN'), None),
        ('EXPORT', same_host_export, None),
        ('DRAIN_STEP', drain_all, None),
        ('PREPARE', handoff_step('S', 'PREPARE', 'xd'), S_STATUS),
        ('COMMIT', handoff_step('S', 'COMMIT', 'checkpoint'), S_STATUS),
        ('SOURCE_RELEASE', release_step, None),
        ('RESERVE', handoff_step('D', 'RESERVE', 'checkpoint'), D_STATUS),
        ('MUTATE', handoff_step('D', 'MUTATE', 'checkpoint'), D_STATUS),
        ('CLAIM', handoff_step('D', 'CLAIM', 'checkpoint'), D_STATUS),
        ('BIND_KILLS_ALL', handoff_step('D', 'BIND_KILLS_ALL', 'checkpoint'), D_STATUS),
        ('PROMOTE_IMPORT', handoff_step('D', 'PROMOTE_IMPORT', 'checkpoint'), D_STATUS),
        ('REPLAY_READY', handoff_step('D', 'REPLAY_READY', 'checkpoint'), D_STATUS),
        ('EXECUTION_START', handoff_step('D', 'EXECUTION_START', 'checkpoint'), D_STATUS),
        ('REKEY_APPLIED', handoff_step('D', 'REKEY_APPLIED', 'checkpoint'), D_STATUS),
        ('ACTIVATE_IMPORT', handoff_step('D', 'ACTIVATE_IMPORT', 'checkpoint'), D_STATUS),
    ],
    # steps whose setup creates the destination VM
    setup={'RESERVE': add_destination})
FLOWS['same-host-abort'] = dict(
    hosts=[('host', False)], destination_host='host', prepare=prepare_same_host,
    steps=[
        ('GATE_BEGIN', handoff_step('S', 'SOURCE_GATE_BEGIN'), None),
        ('EXPORT', same_host_export, None),
        ('PREPARE', handoff_step('S', 'PREPARE', 'xd'), S_STATUS),
        ('ABORT', handoff_step('S', 'ABORT'), S_STATUS),
        ('GATE_ABORT', handoff_step('S', 'SOURCE_GATE_ABORT'), S_STATUS),
    ], setup={})


def rebind_setup(world, ctx):
    # The claimed destination D failed before execution; a replacement VM E
    # on the same host proves D retired and rebinds the empty ticket.
    if world.vms['D'].path.exists():
        world.vms['D'].destroy()
    if 'E' not in world.vms:
        world.vms['E'] = VM(world.hosts['host'], 9, 11, 'guest-a', b'\x44')


FLOWS['same-host-rebind'] = dict(
    hosts=[('host', False)], destination_host='host', prepare=prepare_same_host,
    steps=FLOWS['same-host']['steps'][:9] + [
        ('REBIND_BEGIN', handoff_step('E', 'REBIND_BEGIN', 'checkpoint'), None),
        ('REBIND_STAGE', handoff_step('E', 'REBIND_STAGE', 'checkpoint'), None),
        ('REBIND_EMPTY_READY', handoff_step('E', 'REBIND_EMPTY_READY', 'checkpoint'), None),
        ('REBIND_COMMIT_EMPTY', handoff_step('E', 'REBIND_COMMIT_EMPTY', 'checkpoint'), None),
        ('EXECUTION_START_E', handoff_step('E', 'EXECUTION_START', 'checkpoint'), None),
    ],
    setup={'RESERVE': add_destination, 'REBIND_BEGIN': rebind_setup})


def reset_setup(world, ctx):
    # The mutating destination D died; a later VM resets the mutation.
    if world.vms['D'].path.exists():
        world.vms['D'].destroy()
    if 'E' not in world.vms:
        world.vms['E'] = VM(world.hosts['host'], 9, 11, 'guest-a', b'\x44')


FLOWS['same-host-reset'] = dict(
    hosts=[('host', False)], destination_host='host', prepare=prepare_same_host,
    steps=FLOWS['same-host']['steps'][:8] + [
        ('RESET_MUTATION', handoff_step('E', 'RESET_MUTATION', 'checkpoint'), None),
        ('RESERVE_E', handoff_step('E', 'RESERVE', 'checkpoint'), None),
        ('CANCEL_E', handoff_step('E', 'CANCEL', 'checkpoint'), None),
    ],
    setup={'RESERVE': add_destination, 'RESET_MUTATION': reset_setup})


def prepare_cross_host(world, ctx):
    pairs = setup_keys(world)
    ctx['token'] = hashlib.sha256(b'sweep-cross-token').digest()[:16]
    ctx['checkpoint'] = hashlib.sha256(b'sweep-cross-checkpoint').digest()
    h1 = world.hosts['source-host']
    h1.extra = ['-K', str(pairs['source-host'][0]), '-P',
                str(Path(h1.root) / 'keys' / 'peer.pub')]
    h2 = world.hosts['destination-host']
    h2.extra = ['-K', str(pairs['destination-host'][0]), '-P',
                str(Path(h2.root) / 'keys' / 'peer.pub')]
    world.start()
    src = VM(h1, 7, 9, 'guest-a', b'\x42')
    world.vms['S'] = src
    d = {}
    pc = populate_source(h1, src, d, upload=False, journal=True)
    sha = lambda b: hashlib.sha256(b).digest()
    ctx['deliveries'] = [
        dict(id=pc['del1'], program=pc['prog1'], source=pc['src1'], digest=sha(pc['elf1'])),
        dict(id=pc['del2'], program=pc['prog2'], source=pc['src2'], digest=sha(pc['elf2']))]
    src.handoff('SOURCE_GATE_BEGIN', ctx['token'])
    bundle = src.handoff('EXPORT', ctx['token'], reply='transfer')[1]
    ctx['bundle'] = bundle
    xd = bundle[-32:]
    ctx['release'] = hsa1(pairs['source-host'][0], pairs['source-host'][1],
                          pairs['destination-host'][1], ctx['token'], src.session,
                          7, 9, ctx['checkpoint'], xd, h1.root)
    for sock in (pc['writer'], pc['reader']):
        sock.close()
    world.stop()
    world.vms['D'] = VM(h2, 8, 10, 'guest-a', b'\x43')


FLOWS['cross-host-journal'] = dict(
    hosts=[('source-host', True), ('destination-host', True)],
    destination_host='destination-host', prepare=prepare_cross_host, started=True,
    steps=[
        ('RELEASE_IMPORT', release_import_step, None),
        ('RESERVE', handoff_step('D', 'RESERVE', 'checkpoint'), D_STATUS),
        ('IMPORT', import_step, D_STATUS),
        ('MUTATE', handoff_step('D', 'MUTATE', 'checkpoint'), D_STATUS),
        ('CLAIM', handoff_step('D', 'CLAIM', 'checkpoint'), D_STATUS),
        ('BIND_KILLS_ALL', handoff_step('D', 'BIND_KILLS_ALL', 'checkpoint'), D_STATUS),
        ('BIND_DELIVERY_1', bind_delivery_step(0), None),
        ('BIND_DELIVERY_2', bind_delivery_step(1), None),
        ('DELIVERY_QUERY', delivery_query_step(0), None),
        ('KILL_QUERY', kill_query_step(False), None),
        ('BIND_KILL', kill_query_step(True), None),
        ('PROMOTE_IMPORT', handoff_step('D', 'PROMOTE_IMPORT', 'checkpoint'), D_STATUS),
        ('REPLAY_READY', handoff_step('D', 'REPLAY_READY', 'checkpoint'), D_STATUS),
        ('EXECUTION_START', handoff_step('D', 'EXECUTION_START', 'checkpoint'), D_STATUS),
        ('REKEY_APPLIED', handoff_step('D', 'REKEY_APPLIED', 'checkpoint'), D_STATUS),
        ('ACTIVATE_IMPORT', handoff_step('D', 'ACTIVATE_IMPORT', 'checkpoint'), D_STATUS),
    ], setup={})


# ------------------------------------------------------------ reference
def snapshot(world, directory):
    directory.mkdir(parents=True)
    for name, h in world.hosts.items():
        shutil.copytree(h.root, directory / name, symlinks=True,
                        ignore=shutil.ignore_patterns('sub.sock', 'dtraced.pid',
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
        if flow.get('started'):
            flow['prepare'](world, ctx)
        else:
            world.start()
            flow['prepare'](world, ctx)
            world.stop()
        for name, run, status in flow['steps']:
            snap = base / ('snap-' + name)
            snapshot(world, snap)
            world.start()
            if name in flow['setup']:
                flow['setup'][name](world, ctx)
            reply = run(world, ctx)
            post = status(world, ctx) if status else None
            exits = world.stop()
            record['steps'].append({'step': name, 'reply': reply, 'status': post,
                                    'exits': exits})
            if any(exits.values()):
                raise RuntimeError('reference incarnation exited %r' % exits)
    finally:
        record['logs_tail'] = world.logs()[-2000:]
        world.close()
    record['ctx'] = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in ctx.items()
                     if k != 'deliveries'}
    record['ctx_deliveries'] = [{k: (v.hex() if isinstance(v, bytes) else v)
                                 for k, v in dl.items()} for dl in ctx.get('deliveries', [])]
    (base / 'reference.json').write_text(json.dumps(record, indent=1, default=str))
    return ctx, record


# ----------------------------------------------------------------- sweep
def restored(flow, flowname, step, fault):
    snap = out / flowname / ('snap-' + step)
    world = World(flow, copy_from={n: snap / n for n, _ in flow['hosts']},
                  fault=fault)
    for name, h in world.hosts.items():
        keyed = dict(flow['hosts'])[name]
        if keyed:
            h.extra = ['-K', str(Path(h.root) / 'keys' / 'own.pem'), '-P',
                       str(Path(h.root) / 'keys' / 'peer.pub')]
    return world


def bind_vms(world, ref_vms):
    # VMs live in the snapshot's emulated kernel; a VM created by a later
    # step's setup is created there by that setup.
    for name, (hostname, vmid, epoch, session) in ref_vms.items():
        h = world.hosts[hostname]
        path = h.vmdir / ('vm.%d.%d.guest-a' % (vmid, epoch))
        if path.exists():
            world.vms[name] = VM(h, vmid, epoch, 'guest-a', session, create=False)


def one_point(flowname, index, kind, n, ctx, ref, ref_vms):
    flow = FLOWS[flowname]
    name, run, status = flow['steps'][index]
    world = restored(flow, flowname, name, fault=True)
    result = {'step': name, 'kind': kind, 'n': n}
    try:
        world.start()
        bind_vms(world, ref_vms)
        if name in flow['setup']:
            flow['setup'][name](world, ctx)
        target = None
        for h in world.hosts.values():
            if h.name == (flow['destination_host'] if name in DEST_STEPS[flowname]
                          else source_host(flow)):
                target = h
        Path(target.env['HT_FAULT_FILE']).write_text('%s %d\n' % (kind, n))
        first = run(world, ctx)
        fired_file = Path(target.env['HT_FAULT_FILE'] + '.fired')
        fired = fired_file.read_text().strip() if fired_file.exists() else ''
        Path(target.env['HT_FAULT_FILE']).unlink(missing_ok=True)
        result['fired'] = fired
        result['first'] = first
        exits = world.stop()
        if not fired:
            result['ok'] = first == ref['reply'] and not any(exits.values())
            return result
        # new incarnation, exact retry, reference status, next step
        world.start()
        retry = run(world, ctx)
        if retry != ref['reply']:
            # a second exact retry (bhyve retries after an uncertain reply)
            retry = run(world, ctx)
        result['retry'] = retry
        post = status(world, ctx) if status else None
        result['status'] = post
        ok = retry == ref['reply'] and post == ref['status']
        if index + 1 < len(flow['steps']):
            nname, nrun, _ = flow['steps'][index + 1]
            if nname in flow['setup']:
                flow['setup'][nname](world, ctx)
            nxt = nrun(world, ctx)
            result['next'] = nxt
            ok = ok and nxt == NEXT_REF[flowname][index + 1]
        exits2 = world.stop()
        result['ok'] = ok and not any(exits.values()) and not any(exits2.values())
        return result
    except Exception:
        result['ok'] = False
        result['exception'] = traceback.format_exc()[-1200:]
        return result
    finally:
        logs = world.logs()
        bad = [m for m in SANITIZER if m in logs]
        if bad:
            result['ok'] = False
            result['sanitizer'] = logs[logs.find(bad[0]) - 200:][:2000]
        world.close()


def source_host(flow):
    return flow['hosts'][0][0]


DEST_STEPS, NEXT_REF = {}, {}


def sweep(flowname):
    flow = FLOWS[flowname]
    ctx, record = reference(flowname)
    refs = record['steps']
    NEXT_REF[flowname] = [r['reply'] for r in refs]
    # VM identities in this flow (rebound on every snapshot copy)
    ref_vms = {}
    for vname, (hostname, vmid, epoch, session) in {
            'S': (source_host(flow), 7, 9, b'\x42'),
            'D': (flow['destination_host'], 8, 10, b'\x43'),
            'E': (flow['destination_host'], 9, 11, b'\x44')}.items():
        ref_vms[vname] = (hostname, vmid, epoch, session)
    DEST_STEPS[flowname] = {n for n, _, _ in flow['steps']
                            if n not in ('GATE_BEGIN', 'EXPORT', 'DRAIN_STEP',
                                         'PREPARE', 'COMMIT', 'SOURCE_RELEASE',
                                         'ABORT', 'GATE_ABORT')}
    results = []
    for index, (name, _, _) in enumerate(flow['steps']):
        for kind in kinds:
            n = 0
            batch = jobs
            done = False
            while not done:
                with concurrent.futures.ThreadPoolExecutor(max_workers=batch) as pool:
                    futures = [pool.submit(one_point, flowname, index, kind, k,
                                           ctx, refs[index], ref_vms)
                               for k in range(n, n + batch)]
                    batch_results = [f.result() for f in futures]
                for r in batch_results:
                    results.append(r)
                    if not r.get('fired') and 'exception' not in r:
                        done = True
                n += batch
                if n > 600:
                    results.append({'step': name, 'kind': kind, 'ok': False,
                                    'error': 'more than 600 points'})
                    break
    return record, results


# ---------------------------------------------------------- corrupt mode
def tree_digest(world):
    h = hashlib.sha256()
    for name in sorted(world.hosts):
        root = Path(world.hosts[name].root) / 'state'
        for path in sorted(root.rglob('*')):
            rel = str(path.relative_to(root))
            if path.name.startswith('.handoff-tmp.'):
                continue
            h.update(rel.encode())
            try:
                st = path.lstat()
                h.update(b'%o:%d' % (st.st_mode, st.st_nlink))
                if path.is_file() and not path.is_symlink():
                    h.update(path.read_bytes())
            except OSError:
                h.update(b'?')
    return h.hexdigest()


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
    return True


def one_corruption(flowname, index, host, rel, how, ctx, ref, ref_vms):
    flow = FLOWS[flowname]
    name, run, status = flow['steps'][index]
    world = restored(flow, flowname, name, fault=False)
    result = {'step': name, 'host': host, 'file': rel, 'how': how}
    try:
        target = Path(world.hosts[host].root) / 'state' / rel
        corrupt(target, how)
        try:
            world.start()
        except RuntimeError as exc:
            # fail closed: no socket, nonzero exit
            status_ = world.hosts[host].proc.wait(timeout=20) \
                if world.hosts[host].proc else None
            result['start'] = 'refused (%s)' % status_
            result['ok'] = status_ not in (0, None)
            world.stop()
            return result
        bind_vms(world, ref_vms)
        if name in flow['setup']:
            flow['setup'][name](world, ctx)
        reply = run(world, ctx)
        result['reply'] = reply
        exits = world.stop()
        failed = reply and reply[0] in ('00', 'eof', '')
        result['ok'] = (failed or reply == ref['reply']) and not any(exits.values())
        return result
    except Exception:
        result['ok'] = False
        result['exception'] = traceback.format_exc()[-1200:]
        return result
    finally:
        logs = world.logs()
        bad = [m for m in SANITIZER if m in logs]
        if bad:
            result['ok'] = False
            result['sanitizer'] = logs[logs.find(bad[0]) - 200:][:2000]
        world.close()


def corrupt_sweep(flowname):
    flow = FLOWS[flowname]
    ctx, record = reference(flowname)
    refs = record['steps']
    ref_vms = vm_identities(flow)
    seen, tasks = set(), []
    for index, (name, _, _) in enumerate(flow['steps']):
        snap = out / flowname / ('snap-' + name)
        for host, _ in flow['hosts']:
            state = snap / host / 'state'
            for path in sorted(state.rglob('*')):
                if not path.is_file() or path.name.startswith('.handoff-tmp.') \
                        or path.name.endswith('.lock'):
                    continue
                rel = str(path.relative_to(state))
                key = (host, rel, hashlib.sha256(path.read_bytes()).hexdigest())
                if key in seen:
                    continue
                seen.add(key)
                for how in CORRUPTIONS:
                    tasks.append((index, host, rel, how))
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        results = list(pool.map(lambda t: one_corruption(
            flowname, t[0], t[1], t[2], t[3], ctx, refs[t[0]], ref_vms), tasks))
    return record, results


# ----------------------------------------------------------- refuse mode
def refuse_snapshot(flowname, index, ctx, ref_vms):
    flow = FLOWS[flowname]
    name = flow['steps'][index][0]
    world = restored(flow, flowname, name, fault=False)
    results = []
    try:
        world.start()
        bind_vms(world, ref_vms)
        if name in flow['setup']:
            flow['setup'][name](world, ctx)
        foreign_host = world.hosts[flow['destination_host']]
        world.vms['F'] = VM(foreign_host, 11, 13, 'guest-a', b'\x46')
        digests = {'checkpoint': ctx['checkpoint'], 'transfer': ctx.get('xd', ZERO32),
                   'unrelated': hashlib.sha256(b'unrelated').digest(), 'zero': ZERO32}
        for vname in ('S', 'D', 'E', 'F'):
            v = world.vms.get(vname)
            if v is None or not v.path.exists():
                continue
            for op in OPS:
                if op == 'SOURCE_RELEASE':
                    continue
                for dname, digest in digests.items():
                    before = tree_digest(world)
                    try:
                        ack, _ = v.handoff(op, ctx['token'], digest,
                                           reply={'SOURCE_STATUS': 'status',
                                                  'DESTINATION_STATUS': 'status',
                                                  'EXPORT': 'transfer',
                                                  'SOURCE_DRAIN_STEP': 'step'}.get(op))
                    except (OSError, EOFError) as exc:
                        ack = 'eof'
                    after = tree_digest(world)
                    entry = {'snapshot': name, 'vm': vname, 'op': op,
                             'digest': dname, 'ack': ack}
                    entry['ok'] = ack == '01' or before == after
                    if not entry['ok']:
                        entry['changed'] = True
                    results.append(entry)
        exits = world.stop()
        if any(exits.values()):
            results.append({'snapshot': name, 'ok': False, 'exits': exits})
    except Exception:
        results.append({'snapshot': name, 'ok': False,
                        'exception': traceback.format_exc()[-1200:]})
    finally:
        logs = world.logs()
        bad = [m for m in SANITIZER if m in logs]
        if bad:
            results.append({'snapshot': name, 'ok': False,
                            'sanitizer': logs[logs.find(bad[0]) - 200:][:2000]})
        world.close()
    return results


def refuse_sweep(flowname):
    flow = FLOWS[flowname]
    ctx, record = reference(flowname)
    ref_vms = vm_identities(flow)
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        parts = list(pool.map(lambda i: refuse_snapshot(flowname, i, ctx, ref_vms),
                              range(len(flow['steps']))))
    return record, [r for part in parts for r in part]


def vm_identities(flow):
    return {'S': (source_host(flow), 7, 9, b'\x42'),
            'D': (flow['destination_host'], 8, 10, b'\x43'),
            'E': (flow['destination_host'], 9, 11, b'\x44')}


summary = {}
for flowname in (selected or list(FLOWS)):
    started = time.monotonic()
    record, results = {'fault': sweep, 'corrupt': corrupt_sweep,
                       'refuse': refuse_sweep}[mode](flowname)
    points = [r for r in results if r.get('fired') or mode != 'fault']
    failed = [r for r in results if not r.get('ok')]
    (out / flowname / ('points-%s.json' % mode)).write_text(json.dumps(results, indent=1, default=str))
    summary[flowname] = {'steps': len(record['steps']), 'points': len(points),
                         'failures': len(failed),
                         'seconds': round(time.monotonic() - started)}
    for r in failed[:10]:
        print(json.dumps(r, default=str)[:1500])
    print(flowname, json.dumps(summary[flowname]))
(out / ('summary-%s.json' % mode)).write_text(json.dumps(summary, indent=1))
bad = sum(v['failures'] for v in summary.values())
print('handoff-sweep', mode + ':', json.dumps(summary), 'FAIL' if bad else 'PASS')
raise SystemExit(1 if bad else 0)
