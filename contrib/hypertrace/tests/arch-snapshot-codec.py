#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run the ARM64/RISC-V checkpoint codec tests natively under ASan/UBSan.

Builds tests/sys/vmm/vmm_snapshot_{arm64,riscv}_state_test.c (which include
the production portable codecs and the VMS2 envelope/common-state codecs),
runs every ATF case directly, then rebuilds the suites against deliberately
weakened copies of the codecs ("mutants") and requires each mutant to make at
least one case fail.  Only host userland processes are run: no kernel
module, device, guest or VM is involved, and this is not runtime evidence for
ARM64 or RISC-V hardware.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]
SUITES = {
    'arm64': ('tests/sys/vmm/vmm_snapshot_arm64_state_test.c',
              'sys/arm64/vmm/vmm_snapshot_arm64.c'),
    'riscv': ('tests/sys/vmm/vmm_snapshot_riscv_state_test.c',
              'sys/riscv/vmm/vmm_snapshot_riscv.c'),
}
SHARED = ['sys/dev/vmm/vmm_snapshot_envelope.c',
          'sys/dev/vmm/vmm_snapshot_envelope.h',
          'sys/dev/vmm/vmm_snapshot_state.c',
          'sys/dev/vmm/vmm_snapshot_state.h',
          'sys/dev/vmm/vmm_address_range.h',
          'sys/arm64/vmm/vmm_snapshot_arm64.h',
          'sys/riscv/vmm/vmm_snapshot_riscv.h']
# (suite, name, exact text to remove/replace, replacement)
MUTANTS = [
    ('arm64', 'pstate-aarch32-accepted',
     '(pstate & VMM_SNAPSHOT_ARM64_PSR_M_32) != 0 ||', ''),
    ('arm64', 'private-aplist-duplicate-accepted',
     '(private_listed & (UINT32_C(1) << id)) != 0 ||', ''),
    ('arm64', 'irq-reserved-byte-ignored',
     'if (wire[15] != 0)\n\t\treturn (EINVAL);', ''),
    ('arm64', 'noncritical-known-section-accepted',
     'if (section.flags != ARM64_SECTION_FLAGS)\n\t\t\t\treturn (EINVAL);',
     ''),
    ('arm64', 'aplist-unflagged-spi-accepted',
     '(spi_listed[id / 8] & (1U << (id % 8))) != 0 ||\n'
     '\t\t\t    (dist->spis[id].flags &\n'
     '\t\t\t    VMM_SNAPSHOT_ARM64_IRQ_F_APLIST) == 0',
     '(spi_listed[id / 8] & (1U << (id % 8))) != 0'),
    ('riscv', 'hstatus-forbidden-bits-accepted',
     '(hstatus & ~RISCV_HSTATUS_ALLOWED) != 0 ||', ''),
    ('riscv', 'aplic-reserved-mode-accepted', 'mode == 2 || mode == 3', '0'),
    ('riscv', 'timer-deadline-without-armed-accepted',
     'vcpu->regs[VMM_SNAPSHOT_RISCV_TIMER_DEADLINE] != 0)', '0)'),
]
CFLAGS = ['-std=gnu17', '-g', '-O1', '-Wall', '-Wextra', '-Werror',
          '-Wno-unused-parameter', '-Wno-sign-compare',
          '-fsanitize=address,undefined', '-fno-sanitize-recover=all']

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('output', type=Path)
args = parser.parse_args()
out = args.output.resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
env = dict(os.environ, ASAN_OPTIONS='abort_on_error=1',
           UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=1')


PLATFORM_SOURCES = ['usr.sbin/bhyve/rtc_pl031.c', 'usr.sbin/bhyve/uart_pl011.c',
                    'usr.sbin/bhyve/uart_backend.c']


def build(tree, suite, binary, log):
    if suite == 'platform':
        bhyve = tree / 'usr.sbin/bhyve'
        command = ['cc'] + CFLAGS + [
            '-DBHYVE_SNAPSHOT', '-I', str(bhyve), '-I', str(tree / 'sys'),
            '-I', str(tree / 'lib/libvmmapi'),
            '-I', str(tree / 'contrib/libucl/include'),
            str(tree / 'contrib/hypertrace/tests/arch-snapshot-platform.c')] + \
            [str(tree / src) for src in PLATFORM_SOURCES] + \
            ['-o', str(binary), '-lprivateatf-c']
        result = subprocess.run(command, capture_output=True, text=True)
        log.write_text(' '.join(command) + '\n' + result.stdout +
                       result.stderr)
        return result.returncode, command
    test = tree / SUITES[suite][0]
    command = ['cc'] + CFLAGS + ['-I', str(tree / 'sys'), str(test), '-o',
                                 str(binary), '-lprivateatf-c']
    result = subprocess.run(command, capture_output=True, text=True)
    log.write_text(' '.join(command) + '\n' + result.stdout + result.stderr)
    return result.returncode, command


def run_cases(binary, logdir):
    listing = subprocess.run([str(binary), '-l'], capture_output=True,
                             text=True, check=True).stdout
    cases = re.findall(r'^ident: (\S+)$', listing, re.M)
    results = []
    for case in cases:
        proc = subprocess.run([str(binary), case], capture_output=True,
                              text=True, env=env, timeout=600)
        (logdir / (case + '.log')).write_text(proc.stdout + proc.stderr)
        # ATF prints the result line; the cases' own counters may follow.
        passed = proc.returncode == 0 and \
            'passed' in proc.stdout.splitlines()
        info = [line for line in proc.stdout.splitlines()
                if line != 'passed']
        results.append({'case': case, 'status': proc.returncode,
                        'passed': passed, 'output': info})
    return results


summary = {'suites': {}, 'mutants': [], 'sources': {}}
for rel in [s for pair in SUITES.values() for s in pair] + SHARED:
    summary['sources'][rel] = hashlib.sha256(
        (ROOT / rel).read_bytes()).hexdigest()
for rel in PLATFORM_SOURCES + ['contrib/hypertrace/tests/arch-snapshot-platform.c']:
    summary['sources'][rel] = hashlib.sha256(
        (ROOT / rel).read_bytes()).hexdigest()
ok = True
# "platform" builds the production ARM64 PL011/PL031 checkpoint code with
# shimmed mevent/config/buffer primitives; it has no mutant set.
for suite in list(SUITES) + ['platform']:
    sdir = out / suite
    sdir.mkdir(exist_ok=True)
    binary = sdir / ('vmm_snapshot_%s_test' % suite)
    status, command = build(ROOT, suite, binary, sdir / 'build.log')
    entry = {'build_status': status, 'command': command}
    if status == 0:
        entry['binary_sha256'] = hashlib.sha256(
            binary.read_bytes()).hexdigest()
        entry['cases'] = run_cases(binary, sdir)
        entry['passed'] = sum(1 for c in entry['cases'] if c['passed'])
        entry['total'] = len(entry['cases'])
        ok &= entry['passed'] == entry['total']
    else:
        ok = False
    summary['suites'][suite] = entry
    print(suite, 'build', status, 'cases %s/%s' % (entry.get('passed'),
                                                   entry.get('total')))

for suite, name, old, new in MUTANTS:
    tree = out / 'mutants' / name
    if tree.exists():
        shutil.rmtree(tree)
    for rel in SHARED + list(SUITES[suite]):
        dst = tree / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dst)
    codec = tree / SUITES[suite][1]
    text = codec.read_text()
    if text.count(old) != 1:
        summary['mutants'].append({'name': name, 'error': 'anchor not unique'})
        ok = False
        print('mutant', name, 'ANCHOR-MISMATCH')
        continue
    codec.write_text(text.replace(old, new))
    binary = tree / 'test'
    status, _ = build(tree, suite, binary, tree / 'build.log')
    killed = None
    if status == 0:
        cases = run_cases(binary, tree)
        killed = [c['case'] for c in cases if not c['passed']]
    entry = {'suite': suite, 'name': name, 'build_status': status,
             'killed_by': killed}
    summary['mutants'].append(entry)
    survived = status == 0 and not killed
    ok &= not survived
    print('mutant', name, 'SURVIVED' if survived else
          'killed by %s' % (killed if status == 0 else 'build failure'))

summary['status'] = 0 if ok else 1
(out / 'results.json').write_text(json.dumps(summary, indent=2) + '\n')
print('PASS' if ok else 'FAIL')
raise SystemExit(0 if ok else 1)
