#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Link and run additional dtraced component suites against unmodified objects.

Usage: daemon-extra.py OUTPUT [OBJECTS]

OBJECTS is a native-daemon.py output directory whose sanitized daemon objects
are reused. Without it the production sources are compiled here with the same
flags. The suites never start the daemon, open tracing devices or operate a VM;
fixed system boundaries are replaced only through --wrap symbols listed below.
"""
from pathlib import Path
import concurrent.futures
import json
import os
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
tests = Path(__file__).resolve().parent
daemon = root / 'usr.sbin/dtraced'
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
flags = ['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-Wno-gcc-compat',
         '-DDTRACED_NATIVE_TEST', '-UNDEBUG', '-pthread',
         '-fsanitize=address,undefined', '-ffunction-sections', '-fdata-sections',
         '-I' + str(daemon), '-I' + str(root / 'sys'),
         '-I' + str(root / 'sys/dev/dttransport')]

# suite name -> wrapped symbols. Every suite links all daemon objects except
# dtraced.o (which owns main) unless it lists 'main' itself.
SUITES = {
    'dtt-listen': ['ioctl', 'execve', 'clock_gettime'],
    'dtt-write': ['write', 'socket', 'connect'],
    'dtt-quiesce': ['poll', 'pdwait', 'clock_gettime'],
    'dtt-rekey': ['read', 'write', 'ioctl', 'clock_gettime'],
    'io-wire': ['clock_gettime', 'send', 'recv', 'poll', 'connect', 'getsockopt',
                'sendmsg'],
    'dtt-status': ['clock_gettime'],
    'journal-corruption': [],
    'journal-names': [],
    'launch-child': ['execve', '_exit', 'ioctl'],
    'client-fd': ['ioctl'],
    'header-props': ['_Znwm', 'close'],
    'collector-evidence': ['open', 'close', 'ioctl', 'pdopenpid', 'poll'],
    'child-ledger-recovery': ['sysctlbyname', 'pdopenpid', 'ioctl'],
    'journal-faults': ['openat', 'fsync', 'renameat', 'linkat', 'unlinkat',
                       'fstat', 'write', 'read', 'pread', 'close', 'readdir',
                       'open', 'ioctl'],
    'state-guest': ['ioctl', 'write', 'usleep', 'clock_gettime'],
    'daemon-main': ['main', 'sysctlbyname', 'pidfile_open', 'pidfile_write',
                    'daemon', 'open', 'mkdir', 'remove', 'bind', 'connect',
                    'getsockopt', 'execve', 'ioctl',
                    # request-scoped fault injection (HT_FAULT_FILE)
                    '_ZN7dtraced14client_request6handleEv', 'fsync',
                    'renameat', 'linkat', 'unlinkat', 'fstat', 'fstatat',
                    'mkdirat', 'read', 'pread', 'write', 'flock', 'close',
                    'readdir', 'fdopendir', 'openat', '_Znwm',
                    '_ZN7dtraced3job8send_elfEv',
                    '_ZN7dtraced3job9send_killERNS_5stateE',
                    '_ZN7dtraced3job12send_cleanupERNS_5stateE',
                    '_ZN7dtraced3job9send_infoERNS_5stateE',
                    '_ZN7dtraced3job9read_dataERNS_5stateE',
                    '_ZN7dtraced15process_inboundERNS_3dirEP6dirent',
                    '_ZN7dtraced16process_outboundERNS_3dirEP6dirent',
                    '_ZN7dtraced12process_baseERNS_3dirEP6dirent',
                    '_ZN7dtraced5state10initializeEiiiPPKcS2_S2_',
                    '_ZN7dtraced5state8finalizeEv', 'pthread_create',
                    # process-wide call faults (HT_CALL_FAULT)
                    'kqueue', 'kevent', 'listen', 'socket', 'accept4', 'fcntl',
                    'pdwait', 'pdkill', 'pdfork', 'pipe2', 'socketpair',
                    'setsockopt', 'poll', 'send', 'recv', 'recvmsg', 'shutdown',
                    'pdopenpid',
                    # journal-operation fault entries (FAULT_DIR in daemon-main.cc)
                    '_ZN7dtraced3dir15record_deliveryERKNS_16durable_deliveryENS_14delivery_phaseEb',
                    '_ZN7dtraced3dir11record_killERKNS_12durable_killERKNSt3__18functionIFbRKNS4_6vectorIS1_NS4_9allocatorIS1_EEEEEEE',
                    '_ZN7dtraced3dir19record_kill_appliedERKNS_12durable_killE',
                    '_ZN7dtraced3dir13revoke_sourceEPKh',
                    '_ZN7dtraced3dir22write_data_with_sourceEPKhmS2_',
                    '_ZN7dtraced3dir10write_dataEPhm',
                    '_ZN7dtraced3dir22record_cleanup_pendingERKNS_15durable_cleanupE',
                    '_ZN7dtraced3dir21record_cleanup_queuedERKNS_15durable_cleanupE',
                    '_ZN7dtraced3dir22record_cleanup_appliedERKNS_15durable_cleanupE',
                    '_ZN7dtraced3dir23record_consumer_receiptERKNS_24durable_consumer_receiptENS_22consumer_receipt_phaseE',
                    '_ZN7dtraced3dir25record_consumer_executionERKNS_24durable_consumer_receiptENS_22consumer_receipt_phaseEb',
                    '_ZN7dtraced3dir23record_consumer_programERKNS_24durable_consumer_receiptERKNS_9client_fdE',
                    '_ZN7dtraced3dir24begin_fresh_session_stopERKNS_20durable_session_stopE',
                    '_ZN7dtraced3dir27complete_fresh_session_stopERS0_RKNS_20durable_session_stopE',
                    '_ZN7dtraced3dir25retire_fresh_session_acksERKNS_20durable_session_stopE',
                    '_ZN7dtraced3dir26release_fresh_session_gateERKNS_20durable_session_stopE',
                    '_ZN7dtraced3dir24retire_terminal_deliveryERKNS_16durable_deliveryE',
                    '_ZN7dtraced3dir24retire_accepted_outboundERKNS_16durable_deliveryE',
                    '_ZN7dtraced3dir24recover_consumer_cohortsERKNSt3__16vectorINS_22durable_delivery_stateENS1_9allocatorIS3_EEEE',
                    '_ZN7dtraced3dir27recover_consumer_executionsERKNSt3__16vectorINS_30durable_consumer_receipt_stateENS1_9allocatorIS3_EEEE',
                    '_ZN7dtraced3dir24recover_consumer_processERKNS_24durable_consumer_receiptERNS_24collector_owner_registryE',
                    '_ZN7dtraced3dir24queue_recovered_consumerEPNS_9client_fdE',
                    '_ZN7dtraced3dir24queue_recovered_outboundERKNS_16durable_deliveryEtm',
                    '_ZN7dtraced3dir25guest_rekey_pair_completeERS0_tmtm',
                    '_ZN7dtraced3dir25checkpoint_collector_exitERKNSt3__15arrayIhLm96EEERNS_24collector_owner_registryE',
                    '_ZN7dtraced3dir32checkpoint_consumer_process_exitERKNS_24durable_consumer_receiptERNS_24collector_owner_registryE',
                    '_ZN7dtraced3dir17populate_existingEv',
                    '_ZN7dtraced3dir15list_deliveriesERNSt3__16vectorINS_22durable_delivery_stateENS1_9allocatorIS3_EEEE',
                    '_ZN7dtraced3dir22list_consumer_receiptsERNSt3__16vectorINS_30durable_consumer_receipt_stateENS1_9allocatorIS3_EEEE',
                    '_ZN7dtraced3dir10list_killsERNSt3__16vectorINS_12durable_killENS1_9allocatorIS3_EEEE',
                    '_ZN7dtraced3dir21list_pending_cleanupsERNSt3__16vectorINS_15durable_cleanupENS1_9allocatorIS3_EEEE',
                    '_ZN7dtraced3dir19list_derived_claimsERNSt3__16vectorINS_21durable_derived_claimENS1_9allocatorIS3_EEEE',
                    '_ZN7dtraced3dir24resolve_derived_outboundERS0_PKhS3_RNS_30durable_consumer_receipt_stateE',
                    '_ZN7dtraced3dir28verify_host_delivery_payloadERKNS_16durable_deliveryEPNSt3__16vectorIhNS4_9allocatorIhEEEE',
                    '_ZN7dtraced3dir23verify_pending_outboundERKNS_16durable_deliveryE',
                    '_ZN7dtraced3dir23fresh_session_consumersERS0_RKNS_20durable_session_stopERNSt3__16vectorINS_29host_ingress_program_evidenceENS5_9allocatorIS7_EEEE',
                    '_ZN7dtraced3dir27fresh_consumer_stop_receiptERS0_RKNS_20durable_session_stopERKNS_29host_ingress_program_evidenceEb',
                    '_ZN7dtraced3dir18source_transaction15publish_derivedERKNS_21durable_derived_claimEPKhmPb',
                    ],
}
selected = [s for s in sys.argv[3:]] or [s for s in SUITES
                                         if (tests / (s + '.cc')).exists()]
if selected == ['none']:
    selected = []	# baseline: link the mapping binary only
if any(s not in SUITES for s in selected):
    raise SystemExit('unknown suite')
objects_dir = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 and \
    sys.argv[2] != '-' else None
sources = sorted(daemon.glob('*.cc'))
if objects_dir is None:
    objects_dir = out / 'objects'
    objects_dir.mkdir(exist_ok=True)

    def compile_one(source):
        obj = objects_dir / (source.stem + '.o')
        r = subprocess.run(flags + ['-c', str(source), '-o', str(obj)],
                           capture_output=True, text=True)
        (objects_dir / (source.stem + '-build.log')).write_text(r.stdout + r.stderr)
        return r.returncode
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
        if any(pool.map(compile_one, sources + [tests / 'native-daemon-compat.cc'])):
            raise SystemExit('daemon compilation failed')
    compat = objects_dir / 'native-daemon-compat.o'
else:
    compat = objects_dir / 'native-daemon-compat.o'
objects = [str(objects_dir / (s.stem + '.o')) for s in sources]
missing = [o for o in objects + [str(compat)] if not Path(o).exists()]
if missing:
    raise SystemExit('missing daemon objects: ' + ' '.join(missing))


def link(name):
    wraps = [w for w in SUITES[name] if w != 'main']
    linked = list(objects)
    if 'main' not in SUITES[name]:
        linked = [o for o in linked if Path(o).name != 'dtraced.o']
    command = flags + ['-Wl,--gc-sections', str(tests / (name + '.cc'))] + \
        linked + [str(compat)]
    if wraps:
        command.append('-Wl,' + ','.join('--wrap=' + w for w in wraps))
    command += ['-lcrypto', '-lutil', '-o', str(out / name)]
    r = subprocess.run(command, capture_output=True, text=True)
    log = r.stdout + r.stderr
    status = r.returncode
    if status == 0 and 'main' in SUITES[name]:
        # Regression build: the same main() under an unsigned-char ABI
        # (arm64/riscv64 semantics), where getopt's -1 must still end the
        # option loop.
        unsigned_obj = out / 'dtraced-unsigned-char.o'
        r = subprocess.run(flags + ['-funsigned-char', '-c',
                                    str(daemon / 'dtraced.cc'), '-o',
                                    str(unsigned_obj)], capture_output=True,
                           text=True)
        log += r.stdout + r.stderr
        status = r.returncode
        if status == 0:
            command = [str(unsigned_obj) if Path(c).name == 'dtraced.o' else c
                       for c in command]
            command[-1] = str(out / (name + '-unsigned-char'))
            r = subprocess.run(command, capture_output=True, text=True)
            log += r.stdout + r.stderr
            status = r.returncode
    (out / (name + '-build.log')).write_text(log)
    return name, status


mapping = subprocess.run(flags + objects + [str(compat), '-lcrypto', '-lutil',
                          '-o', str(out / 'dtraced-mapping')],
                         capture_output=True, text=True)
(out / 'dtraced-mapping-build.log').write_text(mapping.stdout + mapping.stderr)
if mapping.returncode:
    raise SystemExit('mapping link failed')
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
    built = list(pool.map(link, selected))
results = []
for name, status in built:
    if status:
        results.append({'case': name, 'phase': 'build', 'status': status})
        continue
    if 'main' in SUITES[name]:
        r = subprocess.run([sys.executable, str(tests / (name + '.py')),
                            str(out / name), str(out / (name + '-run')),
                            str(out / (name + '-unsigned-char'))],
                           capture_output=True, text=True, timeout=1200)
    else:
        r = subprocess.run([str(out / name)], capture_output=True, text=True,
                           timeout=300)
    (out / (name + '.log')).write_text(r.stdout + r.stderr)
    results.append({'case': name, 'phase': 'run', 'status': r.returncode,
                    'tail': (r.stdout + r.stderr)[-400:]})
    if name == 'daemon-main':
        # Registration/replay ordering only races under load: 6 x 15 cycles.
        r = subprocess.run([sys.executable,
                            str(tests / 'registration-order-stress.py'),
                            str(out / name), str(out / 'registration-order-stress'),
                            '6', '15'], capture_output=True, text=True, timeout=1800)
        (out / 'registration-order-stress.log').write_text(r.stdout + r.stderr)
        results.append({'case': 'registration-order-stress', 'phase': 'run',
                        'status': r.returncode,
                        'tail': (r.stdout + r.stderr)[-400:]})
        # Trace continuity (HT-C, a disabled future feature) across real
        # daemon incarnations and two hosts; excluded from the coverage
        # target. The fault/corruption/refusal sweeps over it take ~30
        # minutes and run only with DTRACED_COVERAGE_CONTINUITY=1.
        extra_runs = [('handoff-peers', ['handoff-peers.py', str(out / name),
                                         str(out / 'handoff-peers')])]
        # Live daemon work across real incarnations (live-sweep.py): fault,
        # system-call fault, startup/shutdown, corruption and hostile
        # (including crafted HANDOFF) sweeps; these count toward the target.
        jobs = str(max(2, (os.cpu_count() or 4) * 3 // 4))
        # DTRACED_COVERAGE_SWEEPS=0 skips them for quick development runs;
        # coverage-daemon.py always runs them.
        sweep_modes = () if os.environ.get('DTRACED_COVERAGE_SWEEPS') == '0' else \
            ('fault', 'callfault', 'startup', 'guest-startup', 'hostile', 'corrupt')
        for mode in sweep_modes:
            extra_runs.append(('live-sweep-' + mode,
                               ['live-sweep.py', str(out / name),
                                str(out / ('live-sweep-' + mode)), '--mode', mode,
                                '--jobs', jobs]))
        # HANDOFF from old or crafted peers must be refused without changing
        # state: a security property, always run.
        if sweep_modes:
            extra_runs.append(('handoff-refuse',
                               ['handoff-sweep.py', str(out / name),
                                str(out / 'handoff-refuse'), '--mode', 'refuse',
                                '--jobs', jobs]))
        if os.environ.get('DTRACED_COVERAGE_CONTINUITY') == '1':
            extra_runs.append(('handoff-sweep', ['handoff-sweep.py', str(out / name),
                                                 str(out / 'handoff-sweep'),
                                                 '--kinds', 'sys,oom']))
        for case, argv in extra_runs:
            try:
                r = subprocess.run([sys.executable, str(tests / argv[0]), *argv[1:]],
                                   capture_output=True, text=True, timeout=14400)
                text, status = r.stdout + r.stderr, r.returncode
            except subprocess.TimeoutExpired as exc:
                # record the overrun and continue with the remaining sweeps
                text = ((exc.stdout or b'').decode(errors='replace') +
                        (exc.stderr or b'').decode(errors='replace') +
                        '\nTIMEOUT after 14400 s\n')
                status = 124
            (out / (case + '.log')).write_text(text)
            results.append({'case': case, 'phase': 'run', 'status': status,
                            'tail': text[-400:]})
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
for r in results:
    print(json.dumps({k: v for k, v in r.items() if k != 'tail' or r['status']}))
if any(r['status'] for r in results):
    raise SystemExit(1)
print(f'PASS: {len(results)} additional daemon suites; no daemon started')
