#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Consume kernel-format trace buffers through actual libdtrace offline.

The harness opens libdtrace with dtrace_vopen() and a modeled dtrace(4)
ioctl vector; see consume-ingestion.c.  No tracing device, kernel module,
guest or daemon is used.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: consume-ingestion.py /usr/obj/results /usr/obj/.../amd64.amd64')
root = Path(__file__).resolve().parents[3]
out, obj = (Path(arg).resolve() for arg in sys.argv[1:])
if not all(path.is_relative_to('/usr/obj') for path in (out, obj)) or out.exists():
    raise SystemExit('Use a new /usr/obj output directory and an existing object tree')
out.mkdir(parents=True)
lib = obj / 'cddl/lib/libdtrace'
library = lib / 'libdtrace.so.2'
if not library.exists():
    raise SystemExit('Build libdtrace first')
source = root / 'contrib/hypertrace/tests/consume-ingestion.c'
common = root / 'cddl/contrib/opensolaris/lib/libdtrace/common'
# The coverage object tree keeps generated headers beside its MAKEOBJDIRPREFIX.
prefix = Path(*obj.parts[:obj.parts.index('usr', 3)]) if 'usr' in obj.parts[3:] else obj
includes = [prefix / 'source-includes'] if (prefix / 'source-includes').exists() else []
command = [
    'cc', '-std=gnu17', '-g', '-O1', '-fsanitize=address,undefined',
    '-fno-sanitize-recover=undefined', '-Wall', '-Wextra', '-Werror',
    *('-I' + str(p) for p in includes),
    '-I' + str(root / 'sys'),
    '-I' + str(common),
    '-I' + str(root / 'cddl/contrib/opensolaris/lib/libctf/common'),
    '-I' + str(root / 'cddl/contrib/opensolaris/head'),
    '-I' + str(root / 'sys/cddl/compat/opensolaris'),
    '-I' + str(root / 'cddl/compat/opensolaris/include'),
    '-I' + str(root / 'sys/cddl/contrib/opensolaris/uts/common'),
    str(source), '-L' + str(lib), '-Wl,-rpath,' + str(lib), '-ldtrace',
    '-lelf', '-lxo', '-o', str(out / 'consume-ingestion'),
]
build = subprocess.run(command, capture_output=True, text=True)
(out / 'build.log').write_text(' '.join(command) + '\n' + build.stdout + build.stderr)
if build.returncode:
    raise SystemExit('harness compilation failed; inspect build.log')
env = os.environ.copy()
env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in
    ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=0'
env['UBSAN_OPTIONS'] = 'print_stacktrace=1:halt_on_error=1'
test = subprocess.run([str(out / 'consume-ingestion')], env=env, cwd=out,
    capture_output=True, text=True, timeout=120)
(out / 'run.log').write_text(test.stdout + test.stderr)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
passed = [l.split()[1] for l in test.stdout.splitlines() if l.startswith('PASS ')]
failed = [l.split()[1].rstrip(':') for l in test.stdout.splitlines() if l.startswith('FAIL ')]
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p)
    for p in (library, source, Path(__file__).resolve())},
    'scope': 'dtrace_vopen with a modeled dtrace(4) vector; scripted firings; '
    'no device, kernel, DIF execution, guest or daemon'}, indent=2) + '\n')
# Structured output written by case_oformat, checked as parsed JSON.
oformat_ok = False
try:
    doc = json.loads((out / 'oformat.json').read_text())
    probe, agg = doc['dtrace']['probes']
    oformat_ok = (
        {k: probe[k] for k in ('cpu', 'id', 'provider', 'module', 'function', 'name')} ==
        {'cpu': 0, 'id': 4, 'provider': 'test', 'module': 'kernel',
         'function': 'alpha', 'name': 'entry'} and
        probe['output'] == [{'message': 'alpha:5\n'}, {'value': 'alpha'},
                            {'value': 5}, {'value': 7}] and
        agg == {'keys': [{'value': 'alpha'}], 'count': 1})
except (OSError, ValueError, KeyError, TypeError) as error:
    print('oformat.json:', error)
# Histograms, avg/stddev, symbol/stack keys and principal-buffer symbols:
# two firings with arg2 = 1 and 3 (expected values follow D semantics).
oformat2_ok = False
try:
    doc = json.loads((out / 'oformat2.json').read_text())['dtrace']['probes']
    frames = [{'symbol': 'kernel`vm_fault+0x10', 'module': 'kernel',
               'name': 'vm_fault', 'offset': '0x10'},
              {'symbol': 'kernel`sched_tick', 'module': 'kernel',
               'name': 'sched_tick'}]
    sym = {'sym': 'kernel`vm_fault', 'object': 'kernel', 'name': 'vm_fault'}
    entry_out = [{'stack-frames': frames}, sym, {'mod': 'kernel'},
                 {'tracemem': '0x44540158'}]
    probes = [p for p in doc if 'name' in p]
    aggs = [p for p in doc if 'name' not in p]
    printa = [p for p in probes if p['name'] == 'return'][0]['output'][0]
    oformat2_ok = (
        [p['output'] for p in probes if p['name'] == 'entry'] == [entry_out] * 2 and
        printa['aggregation-name'] == 'q' and
        printa['aggregation-data'] == [{'keys': [], 'buckets': [
            {'value': 0, 'count': 0}, {'value': 1, 'count': 1},
            {'value': 2, 'count': 1}, {'value': 4, 'count': 0}]}] and
        # printa(@q) marked @q printed, so the final print omits it.
        aggs[0]['buckets'] == [{'value': 0, 'count': 0}, {'value': 1, 'count': 1},
            {'value': 2, 'count': 0}, {'value': 3, 'count': 1},
            {'value': 4, 'operator': '>=', 'count': 0}] and
        aggs[1]['buckets'] == [{'value': 1, 'count': 0, 'operator': '<'},
            {'value': 1, 'count': 1}, {'value': 2, 'count': 1},
            {'value': 4, 'count': 0}] and
        aggs[2] == {'keys': [], 'average': 2} and
        aggs[3] == {'keys': [], 'stddev': 1} and
        aggs[4] == {'keys': [sym, {'mod': 'kernel'}], 'count': 2} and
        aggs[5] == {'keys': [{'stack-frames': frames}], 'count': 2} and
        len(aggs) == 6)
except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
    print('oformat2.json:', error)
if 'oformat-aggregations' in passed and not oformat2_ok:
    passed.remove('oformat-aggregations')
    failed.append('oformat-aggregations')
if 'oformat-json' in passed and not oformat_ok:
    passed.remove('oformat-json')
    failed.append('oformat-json')
(out / 'results.json').write_text(json.dumps({'returncode': test.returncode,
    'passed': passed, 'failed': failed}, indent=2) + '\n')
if test.returncode or failed or not passed:
    print(test.stdout[-4000:], test.stderr[-4000:])
    raise SystemExit('consume ingestion failed; inspect run.log')
print('PASS:', len(passed), 'trace-buffer ingestion cases')
