#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Rootless tests of native HyperTrace code; does not load modules or run VMs."""
from pathlib import Path
import concurrent.futures
import json
import os
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
tests = Path(__file__).resolve().parent
if len(sys.argv) != 2:
    raise SystemExit('usage: native-port.py /usr/obj/<validation-directory>')
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
for name in ('machine', 'x86'):
    link = out / name
    target = root / 'sys' / ('amd64' if name == 'machine' else name) / 'include'
    if link.is_symlink():
        if link.resolve() != target:
            raise SystemExit(f'Unexpected header symlink: {link}')
    elif link.exists():
        raise SystemExit(f'Header path already exists: {link}')
    else:
        link.symlink_to(target)

def run_case(name):
    command = ['cc', '-Wall', '-Wextra', '-Werror', '-pthread', '-UNDEBUG',
               '-fsanitize=address,undefined', '-I' + str(out),
               '-I' + str(root / 'usr.sbin/bhyve'),
               '-I' + str(root / 'usr.sbin/dtraced'),
               '-I' + str(root / 'lib/libvmmapi')]
    if name == 'bhyve-device':
        command += ['-DBHYVE_SNAPSHOT=1', '-Wno-unused-function', '-Wno-unused-variable',
                    '-Wno-unused-parameter', '-ffunction-sections',
                    '-fdata-sections', '-Wl,--gc-sections',
                    '-Wl,--wrap=pthread_create',
                    '-I' + str(root / 'sys'),
                    '-I' + str(root / 'contrib/libucl/include')]
    if name in ('bhyve-sockets', 'bhyve-connect'):
        command += ['-I' + str(root / 'sys')]
    if name == 'bhyve-connect':
        command += ['-Wl,--wrap=connectat,--wrap=open,--wrap=pthread_create']
    if name == 'checkpoint-release':
        command += ['-ffunction-sections', '-fdata-sections',
                    '-Wl,--gc-sections', '-I' + str(root / 'sys')]
    if name in ('cli-frame', 'cli-identifiers'):
        command += ['-I' + str(root / 'sys'),
                    '-I' + str(root / 'cddl/contrib/opensolaris/cmd/dtrace')]
    if name == 'control-client':
        command += ['-Wno-unused-function', '-Wno-unused-parameter',
                    '-I' + str(root / 'usr.sbin/dtracedctl')]
    if name == 'hashmap':
        command += ['-Wl,--wrap=malloc',
                    '-I' + str(root / 'cddl/contrib/opensolaris/lib/libdtrace/common')]
    if name == 'cpuid-discovery':
        command += ['-I' + str(root / 'sys/amd64/include')]
    extension = '.c'
    if name == 'elf-bounds':
        command[0] = 'c++'
        extension = '.cc'
        command += ['-I' + str(root / 'cddl/contrib/opensolaris/lib/libdtrace/common')]
    command += [str(tests / (name + extension)), '-o', str(out / name)]
    if name in ('bhyve-device', 'bhyve-sockets', 'bhyve-connect',
                'transfer-wire'):
        command += ['-lcrypto']
    if name == 'checkpoint-release':
        command += ['-lmd']
    compiled = subprocess.run(command, capture_output=True, text=True)
    (out / (name + '-build.log')).write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        return {'case': name, 'phase': 'build', 'status': compiled.returncode}
    result = subprocess.run([str(out / name)], capture_output=True, text=True,
                            timeout=30)
    (out / (name + '.log')).write_text(result.stdout + result.stderr)
    return {'case': name, 'phase': 'run', 'status': result.returncode}

cases = ('elf-bounds', 'cpuid-discovery', 'elf-fragments', 'bhyve-sockets', 'bhyve-connect', 'bhyve-device', 'checkpoint-release', 'control-client', 'cli-frame', 'cli-identifiers', 'attestation-fd', 'hashmap', 'transfer-wire')
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
    results = list(pool.map(run_case, cases))
for name in ('collector-owner-retention', 'collector-process-proof', 'collector-handle-query', 'library-handle-lifetime', 'dtrace-handle-lifetime', 'fresh-stop-progress', 'collector-startup-recovery', 'migration-recover-cli', 'migration-source-control', 'migration-ipc-quarantine', 'migration-source-intent', 'migration-restart-command', 'recovery-query-gate', 'vm-destroy-identity', 'migration-receiver', 'migration-recovery-exchange', 'migration-retained-owner', 'migration-dest-image', 'migration-dest-reconstruct', 'gdb-migration-fence', 'migration-rollback-repair', 'migration-credentials', 'migration-tls', 'migration-journal-adapter', 'migration-recovery', 'migration-fresh-destination', 'migration-fresh-source', 'migration-production-retire', 'retire-transport', 'retire-cpus', 'ipc-startup', 'retire-acpi', 'retire-console', 'migration-cpu-barrier', 'migration-production-binding', 'migration-session-core', 'migration-fresh-preflight', 'migration-source-storage', 'migration-source-admission', 'fresh-session-restore', 'fresh-session-checkpoint-stop', 'fresh-session-load', 'guest-fresh-wait', 'session-host-gate', 'restore-handoff-preflight', 'riscv-cpu-contract', 'arm64-stage-walk', 'procdesc-birth', 'difo-ownership', 'dif-array-verifier', 'vprobe-enable', 'vprobe-match', 'pagewalk', 'probe-map', 'probe-ioctl', 'probe-entry', 'guest-builtins', 'guest-pushtr', 'guest-driver', 'guest-delivery-rekey', 'guest-delivery-key', 'guest-rekey-receipt', 'guest-rekey-startup', 'guest-rekey-cleanup', 'transport-registration', 'transport-queue', 'transport-read', 'guest-recovery-identity', 'probe-batch', 'dtrace-epoch-fence', 'hypertrace-epoch-query', 'consumer-quiesced-drain', 'consumer-speculation-kernel', 'consumer-drain-receiver', 'consumer-drain-sender', 'consumer-stop-sender', 'consumer-stop-receiver', 'consumer-descendants', 'consumer-output-discard', 'library-transport', 'consumer-reconnect', 'consumer-ack-reconnect', 'consumer-derived-replay', 'consumer-session-file', 'consumer-birth-ident', 'consumer-restart-owner', 'consumer-execution', 'consumer-execution-wire', 'consumer-execution-queue', 'cli-info', 'guest-daemon', 'augment-ioctl', 'probe-owner', 'vm-reset', 'vm-destroy-checked', 'packet-provenance', 'packet-v2-auth', 'packet-v2-tunread', 'packet-v2-bhyve', 'packet-v2-checkpoint', 'packet-v2-freeze', 'guest-arg-bounds', 'guest-register-map', 'guest-uregs', 'guest-ucaller', 'guest-ustack-format', 'riscv-version', 'guest-host-stack', 'guest-pcstack-action', 'guest-pcstack-format', 'guest-hvtime', 'guest-immstack-size', 'guest-userload', 'guest-copyout', 'guest-write-pagewalk', 'guest-restricted-load', 'guest-store', 'guest-var-copy', 'guest-byref-authority', 'guest-dynvar-copy', 'guest-byte-copy', 'guest-memref', 'guest-symbol-actions', 'guest-panic-action', 'guest-predicate-cache', 'guest-casefold', 'guest-json-scratch', 'guest-strjoin', 'guest-scalar-read', 'guest-amd64-copy', 'guest-key-compare', 'packet-v2-epoch', 'packet-v2-sidecar', 'vtnet-packet-id', 'provider-userstack', 'restore-private-image'):
    result = subprocess.run([sys.executable, str(tests / (name + '.py')),
                             str(out / name)], capture_output=True, text=True,
                            timeout=60)
    (out / (name + '.log')).write_text(result.stdout + result.stderr)
    results.append({'case': name, 'phase': 'run', 'status': result.returncode})
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
for result in results:
    print(result)
if any(result['status'] != 0 for result in results):
    raise SystemExit(1)
print(f'PASS: {len(results)} native port suites; no live VM or module execution')
