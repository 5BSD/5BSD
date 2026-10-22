#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""HyperTrace VM handoff across real dtraced incarnations and peers.

Usage: handoff-peers.py BINARY OUTPUT

BINARY is the daemon-main test executable: the actual dtraced objects plus
the daemon-main.cc boundary shim. Every daemon runs offline in a private
/tmp root; HT_VMDIR gives it an emulated VMM/HyperTrace kernel (VM
attestation by descriptor, VM liveness, the per-epoch DTrace gate), whose
state persists across daemon restarts like kernel state does. No device,
VM, installed daemon or network is used.

The peers speak the bhyve protocol (usr.sbin/bhyve/hypertrace.c): each
handoff request is one fresh attested forwarder connection carrying one
DTRACED_MSG_HANDOFF frame, answered by a status byte and an optional reply
(48-byte status, HTX1 transfer, drain step, release attestation). Daemons
are stopped and restarted between protocol steps (new incarnations over the
same journals), and a second daemon acts as a different host for signed
source-release import.

Oracles: status replies decoded from the wire, the transfer bundle's own
SHA-256 trailer, the HSA1 release checks bhyve applies (fixed fields and
both internal SHA-256 digests), and the journal files each step must (or
must not) leave on disk.
"""
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
import time

import htpeerlib
from htpeerlib import *

binary, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
assert binary.is_relative_to('/usr/obj') and out.is_relative_to('/usr/obj')
out.mkdir(parents=True, exist_ok=True)
htpeerlib.binary = binary
results = []


def scenario(name):
    def register(body):
        started = time.monotonic()
        detail, ok, hosts = {}, False, []
        try:
            ok = body(detail, hosts)
        except Exception as exc:
            import traceback
            detail['exception'] = traceback.format_exc()[-1500:]
        finally:
            for h in hosts:
                status = h.stop()
                detail.setdefault('exit', {})[h.name] = status
                if status != 0:
                    ok = False
                detail.setdefault('logs', {})[h.name] = h.logs[-1:] if not ok else []
                if getattr(h, 'debug', None):
                    detail.setdefault('debug', {})[h.name] = h.debug[:40]
                h.close()
        results.append({'case': name, 'passed': bool(ok), 'detail': detail,
                        'seconds': round(time.monotonic() - started, 1)})
        return body
    return register


def source_export(src, token, d):
    ack, bundle = src.handoff('SOURCE_GATE_BEGIN', token)
    d['gate'] = ack
    d['gate_journal'] = src.host.has('.gate.')
    ack, bundle = src.handoff('EXPORT', token, reply='transfer')
    d['export'] = ack
    if bundle is None or not transfer_valid(bundle, token):
        d['bundle_invalid'] = True
        return None
    return bundle


def drain(src, token, digest, d):
    steps = 0
    while True:
        ack, more = src.handoff('SOURCE_DRAIN_STEP', token, digest, reply='step')
        if ack != '01':
            d['drain_ack'] = ack
            return False
        steps += 1
        if more == 0:
            d['drain_steps'] = steps
            return True
        if steps > 8:
            return False


@scenario('same-host-empty-handoff-across-restarts')
def same_host_empty(d, hosts):
    host = Daemon('host')
    hosts.append(host)
    host.start()
    token = os.urandom(16)
    checkpoint = hashlib.sha256(b'checkpoint manifest').digest()
    src = VM(host, 7, 9, 'guest-a', b'\x42')
    bundle = source_export(src, token, d)
    xd = bundle[-32:]
    host.restart()				# incarnation 2: gate survives
    ok = drain(src, token, xd, d)
    d['prepare'] = src.handoff('PREPARE', token, xd)[0]
    host.restart()				# incarnation 3
    ack, st = src.handoff('SOURCE_STATUS', token, reply='status')
    d['source_status'] = st is not None and st['phase'] == 'p' and st['digest'] == xd
    d['commit'] = src.handoff('COMMIT', token, checkpoint)[0]
    d['commit_retry'] = src.handoff('COMMIT', token, checkpoint)[0]
    ack, st = src.handoff('SOURCE_STATUS', token, reply='status')
    d['committed'] = st is not None and st['phase'] == 'c' and st['digest'] == checkpoint
    # release: authenticate the channel while the VMM lives, then destroy it
    rel = src.channel(SUB_SOURCE_RELEASE | SUB_ADMISSION_ACK)
    d['release_admitted'] = recv_exact(rel, 1).hex()
    src.destroy()
    frame(rel, header(MSG_HANDOFF), bytes([OPS['SOURCE_RELEASE']]) + token + checkpoint)
    d['release'] = recv_exact(rel, 1).hex()
    d['release_mode'] = recv_exact(rel, 1).hex()
    rel.close()
    d['released_journal'] = host.has('.released.')
    host.restart()				# incarnation 4
    dst = VM(host, 8, 10, 'guest-a', b'\x43')
    d['rebind_on_committed'] = dst.handoff('REBIND_BEGIN', token, checkpoint)[0]
    ack, st = dst.handoff('DESTINATION_STATUS', token, checkpoint, reply='status')
    d['dst_committed'] = st is not None and st['phase'] == 'c'
    steps = {}
    for op, phase in (('RESERVE', 'v'), ('MUTATE', 'm'), ('CLAIM', 'r')):
        steps[op] = dst.handoff(op, token, checkpoint)[0]
        host.restart()
        ack, st = dst.handoff('DESTINATION_STATUS', token, checkpoint, reply='status')
        steps[op + '_status'] = st['phase'] if st else ack
    for op in ('BIND_KILLS_ALL', 'PROMOTE_IMPORT', 'REPLAY_READY',
               'EXECUTION_START', 'REKEY_APPLIED', 'ACTIVATE_IMPORT'):
        steps[op] = dst.handoff(op, token, checkpoint)[0]
    host.restart()
    for op in ('EXECUTION_START', 'ACTIVATE_IMPORT'):	# idempotent retries
        steps[op + '_retry'] = dst.handoff(op, token, checkpoint)[0]
    d['steps'] = steps
    d['start_journal'] = host.has('.handoff-start.')
    d['applied_journal'] = host.has('.handoff-applied.')
    # a different VM cannot drive the claimed ticket
    other = VM(host, 9, 11, 'guest-a', b'\x44')
    d['foreign_claim'] = other.handoff('CLAIM', token, checkpoint)[0]
    d['incarnations'] = host.incarnations
    return (ok and d['gate'] == '01' and d['gate_journal'] and
            d['export'] == '01' and d['prepare'] == '01' and d['source_status'] and
            d['commit'] == '01' and d['commit_retry'] == '01' and d['committed'] and
            d['release_admitted'] == '01' and d['release'] == '01' and
            d['release_mode'] == '00' and d['released_journal'] and
            d['rebind_on_committed'] == '00' and d['dst_committed'] and
            steps['RESERVE_status'] == 'v' and steps['MUTATE_status'] == 'm' and
            steps['CLAIM_status'] == 'r' and
            all(v == '01' for k, v in steps.items() if not k.endswith('_status')) and
            d['start_journal'] and d['applied_journal'] and d['foreign_claim'] == '00')


@scenario('same-host-nonempty-source-refused')
def same_host_nonempty(d, hosts):
    # PREPARE keeps a nonempty source closed (EOPNOTSUPP: "a source must not
    # release until nonempty restore is recoverable"); the exported bundle is
    # still a valid HTX1 and the gate can be resumed.
    host = Daemon('host')
    hosts.append(host)
    host.start()
    src = VM(host, 7, 9, 'guest-a', b'\x42')
    ctx = populate_source(host, src, d, upload=True, journal=True)
    token = os.urandom(16)
    bundle = source_export(src, token, d)
    xd = bundle[-32:] if bundle else ZERO32
    d['drain'] = src.handoff('SOURCE_DRAIN_STEP', token, xd, reply='step')[0]
    d['prepare'] = src.handoff('PREPARE', token, xd)[0]
    ack, st = src.handoff('SOURCE_STATUS', token, reply='status')
    d['status_phase'] = st['phase'] if st else ack
    d['gate_abort'] = src.handoff('SOURCE_GATE_ABORT', token)[0]
    d['gate_after'] = host.has('.gate.')
    ctx['hc'].close()
    for sock in (ctx['writer'], ctx['reader']):
        sock.close()
    return (d['gate'] == '01' and d['export'] == '01' and bundle is not None and
            d['drain'] == '00' and d['prepare'] == '00' and d['status_phase'] == '' and
            d['gate_abort'] == '01' and not d['gate_after'] and d['executed'])


def cross_host(d, hosts, upload, journal):
    keydir = Path(tempfile.mkdtemp(prefix='htk-', dir='/tmp'))
    k1, k1pub = make_keys(keydir, 'source')
    k2, k2pub = make_keys(keydir, 'destination')
    h1 = Daemon('source-host', ['-K', str(k1), '-P', str(k2pub)])
    h2 = Daemon('destination-host', ['-K', str(k2), '-P', str(k1pub)])
    hosts += [h1, h2]
    h1.start()
    h2.start()
    src = VM(h1, 7, 9, 'guest-a', b'\x42')
    ctx = populate_source(h1, src, d, upload=upload, journal=journal)
    token = os.urandom(16)
    checkpoint = hashlib.sha256(b'cross-host checkpoint').digest()
    bundle = source_export(src, token, d)
    xd = bundle[-32:]
    d['bundle_bytes'] = len(bundle)
    d['source_prepare_refused'] = src.handoff('PREPARE', token, xd)[0]
    release = hsa1(k1, k1pub, k2pub, token, src.session, 7, 9, checkpoint, xd, keydir)
    d['release_shape'] = release_valid(release, token, checkpoint, xd)
    if 'hc' not in ctx:
        ctx['hc'] = HostConsumer(h1)
    ctx['hc'].close()
    # destination host: the same consumer process reconnects there
    hc2 = HostConsumer.__new__(HostConsumer)
    hc2.__dict__.update(dict(host=h2, session=ctx['hc'].session, birth=ctx['hc'].birth,
                             ident=ctx['hc'].ident, digest=ctx['hc'].digest,
                             received=[], drains=[], stops=[], executions=[],
                             execute=True, ingress_session=ctx['hc'].ingress_session,
                             lock=threading.Lock()))
    hc2.connect()
    dst = VM(h2, 8, 10, 'guest-a', b'\x43')
    steps = d['steps'] = {}
    ack, _ = request(dst, MSG_HANDOFF_RELEASE_IMPORT, token + checkpoint + release, status=False)
    steps['RELEASE_IMPORT'] = ack
    steps['RESERVE'] = dst.handoff('RESERVE', token, checkpoint)[0]
    s = dst.channel()
    frame(s, header(MSG_HANDOFF_IMPORT), token + checkpoint + bundle)
    steps['IMPORT'] = s.recv(1).hex()
    s.close()
    h2.restart()
    hc2.close()
    hc2.connect()
    if not journal:
        # a foreign transfer carrying host ingress is refused at MUTATE
        # (no local HSL1); the reservation can still be cancelled
        steps['MUTATE'] = dst.handoff('MUTATE', token, checkpoint)[0]
        steps['CANCEL'] = dst.handoff('CANCEL', token, checkpoint)[0]
        ack, st = dst.handoff('DESTINATION_STATUS', token, checkpoint, reply='status')
        steps['after_cancel'] = st['phase'] if st else ack
        hc2.close()
        shutil.rmtree(keydir)
        d['ingress_refused'] = (steps['RELEASE_IMPORT'] == '01' and
                                steps['RESERVE'] == '01' and steps['IMPORT'] == '01' and
                                steps['MUTATE'] == '00' and steps['CANCEL'] == '01' and
                                steps['after_cancel'] == 'c')
        return d['ingress_refused']
    for op in ('MUTATE', 'CLAIM', 'BIND_KILLS_ALL'):
        steps[op] = dst.handoff(op, token, checkpoint)[0]
    sha = lambda b: hashlib.sha256(b).digest()
    if journal:
        ack, st = request(dst, MSG_HANDOFF_BIND_DELIVERY, delivery_wire(
            token, checkpoint, ctx['del1'], ctx['prog1'], ctx['src1'], 0, sha(ctx['elf1'])))
        steps['BIND_DELIVERY_1'] = (ack, st['phase'] if st else None)
        ack, st = request(dst, MSG_HANDOFF_BIND_DELIVERY, delivery_wire(
            token, checkpoint, ctx['del2'], ctx['prog2'], ctx['src2'], 0, sha(ctx['elf2'])))
        steps['BIND_DELIVERY_2'] = (ack, st['phase'] if st else None)
    ack, st = request(dst, MSG_HANDOFF_DELIVERY, delivery_wire(
        token, checkpoint, 601, b'\xa1', b'\xb1', 3))
    steps['HOST_DELIVERY'] = (ack, st and st['phase'])
    ack, st = request(dst, MSG_HANDOFF_KILL, kill_wire(token, checkpoint, 4242, b'\x53'))
    steps['KILL'] = (ack, st['phase'] if st else None, st['revoked'] if st else None)
    steps['PROMOTE_IMPORT'] = dst.handoff('PROMOTE_IMPORT', token, checkpoint)[0]
    h2.restart()
    hc2.close()
    hc2.connect()
    conn = Connector(dst)
    steps['admission'] = conn.admission
    steps['replay_kills'] = len(conn.manifest)
    ready = wait_until(lambda: dst.handoff('REPLAY_READY', token, checkpoint)[0] == '01', 10)
    steps['REPLAY_READY'] = '01' if ready else '00'
    steps['replayed_frames'] = len(conn.frames)
    for op in ('EXECUTION_START', 'REKEY_APPLIED', 'ACTIVATE_IMPORT'):
        steps[op] = dst.handoff(op, token, checkpoint)[0]
    d['imported_to_consumer'] = wait_until(lambda: len(hc2.received) >= 1, 10)
    d['imported_executions'] = list(hc2.executions)
    conn.close()
    hc2.close()
    shutil.rmtree(keydir)
    d['h2_outbound'] = [n for n in h2.files() if not n.startswith('elf.')][:60]
    d['h2_inbound'] = [n for n in h2.files('inbound') if not n.startswith('elf.')][:60]
    if journal:
        return (d['source_prepare_refused'] == '00' and d['release_shape'] and
                all(steps[k] == '01' for k in (
                    'RELEASE_IMPORT', 'RESERVE', 'IMPORT', 'MUTATE', 'CLAIM',
                    'BIND_KILLS_ALL', 'PROMOTE_IMPORT', 'REPLAY_READY',
                    'EXECUTION_START', 'REKEY_APPLIED', 'ACTIVATE_IMPORT')) and
                steps['BIND_DELIVERY_1'] == ('01', 'a') and
                steps['BIND_DELIVERY_2'] == ('01', 'a') and
                steps['KILL'] == ('01', 'a', 1) and steps['admission'] == '01' and
                steps['replay_kills'] == 1 and
                any(n.startswith('.handoff-start.') for n in d['h2_outbound']))
    return d['ingress_refused']


@scenario('cross-host-journal-import')
def cross_host_journal(d, hosts):
    return cross_host(d, hosts, upload=False, journal=True)


@scenario('cross-host-ingress-import')
def cross_host_ingress(d, hosts):
    return cross_host(d, hosts, upload=True, journal=False)


(out / 'results.json').write_text(json.dumps(results, indent=2, default=str) + '\n')
failed = [r for r in results if not r['passed']]
for r in failed:
    print(json.dumps(r, default=str)[:3000])
print('handoff-peers:', len(results), 'scenarios;', len(failed), 'failures')
raise SystemExit(1 if failed else 0)
