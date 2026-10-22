#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Consumer record handling through actual libdtrace, offline.

Extends consume-ingestion with output-failure propagation, malformed record
descriptions, histogram and structured-output edge cases, temporal drops,
snapshot failures, allocation-failure sweeps and the work loop.  The harness
(consume-records.c) reuses the dtrace(4) model of consume-ingestion.c through
dtrace_vopen(); no tracing device, kernel module, guest or daemon is used.

usage: consume-records.py /usr/obj/new-results /usr/obj/.../amd64.amd64
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: consume-records.py /usr/obj/results /usr/obj/.../amd64.amd64')
root = Path(__file__).resolve().parents[3]
out, obj = (Path(arg).resolve() for arg in sys.argv[1:])
if not all(path.is_relative_to('/usr/obj') for path in (out, obj)) or out.exists():
    raise SystemExit('Use a new /usr/obj output directory and an existing object tree')
out.mkdir(parents=True)
lib = obj / 'cddl/lib/libdtrace'
library = lib / 'libdtrace.so.2'
if not library.exists():
    raise SystemExit('Build libdtrace first')
tests = root / 'contrib/hypertrace/tests'
sources = [tests / 'consume-records.c', tests / 'consume-records-internal.c',
           tests / 'consume-ingestion.c', Path(__file__).resolve()]
common = root / 'cddl/contrib/opensolaris/lib/libdtrace/common'
prefix = Path(*obj.parts[:obj.parts.index('usr', 3)]) if 'usr' in obj.parts[3:] else obj
includes = [prefix / 'source-includes'] if (prefix / 'source-includes').exists() else []
incflags = [*('-I' + str(p) for p in includes), '-I' + str(tests),
            '-I' + str(root / 'sys'), '-I' + str(common),
            '-I' + str(root / 'cddl/contrib/opensolaris/lib/libctf/common'),
            '-I' + str(root / 'cddl/contrib/opensolaris/head'),
            '-I' + str(root / 'sys/cddl/compat/opensolaris'),
            '-I' + str(root / 'cddl/compat/opensolaris/include'),
            '-I' + str(root / 'sys/cddl/contrib/opensolaris/uts/common')]
# dt_impl.h consumers (the internal translation unit) need libdtrace's own
# preprocessor configuration.
libflags = subprocess.run(['make', '-V', 'CFLAGS', '-C', str(root / 'cddl/lib/libdtrace'),
    '-m', str(root / 'share/mk'), 'SRCTOP=' + str(root), 'SRCCONF=/dev/null',
    '__MAKE_CONF=/dev/null'], capture_output=True, text=True).stdout.split()
libdefs = [f for f in libflags if f.startswith(('-D', '-I'))]
builds = {
    'consume-records': ['-fsanitize=address,undefined'],
    # Without ASan so that the harness can interpose malloc().
    'consume-records-fault': ['-fsanitize=undefined', '-DFAULT_MALLOC'],
}
log = []
for name, san in builds.items():
    internal = out / (name + '-internal.o')
    cmds = [
        ['cc', '-std=gnu17', '-g', '-O1', *san, '-fno-sanitize-recover=undefined',
         '-Wno-unused-parameter', *libdefs, *incflags, '-c',
         str(tests / 'consume-records-internal.c'), '-o', str(internal)],
        ['cc', '-std=gnu17', '-g', '-O1', *san, '-fno-sanitize-recover=undefined',
         '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', *incflags,
         str(tests / 'consume-records.c'), str(internal), '-L' + str(lib),
         '-Wl,-rpath,' + str(lib), '-ldtrace', '-lproc', '-lelf', '-lxo', '-lpthread',
         '-o', str(out / name)],
    ]
    for cmd in cmds:
        build = subprocess.run(cmd, capture_output=True, text=True)
        log.append(' '.join(cmd) + '\n' + build.stdout + build.stderr)
        if build.returncode:
            (out / 'build.log').write_text('\n'.join(log))
            raise SystemExit('harness compilation failed; inspect build.log')
(out / 'build.log').write_text('\n'.join(log))
env = os.environ.copy()
env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in
    ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=0'
env['UBSAN_OPTIONS'] = 'print_stacktrace=1:halt_on_error=1'
# Each run is a separate process because some library choices are made once
# per process (packed-glyph detection, cached CPU counts).
runs = [
    ('consume-records', [], {}),
    # Structured output: one libxo document per process.
    ('consume-records', ['oformat-records'], {}),
    ('consume-records', ['oformat-aggregations'], {}),
    ('consume-records', ['oformat-drops'], {}),
    ('consume-records', ['oformat-drops-temporal'], {}),
    ('consume-records', ['oformat-errors'], {}),
    ('consume-records', ['quiesced-oformat'], {}),
    ('consume-records', ['oformat-edges'], {}),
    ('consume-records', ['oformat-more'], {}),
    ('consume-records', ['packed-term', 'auto'], {'TERM': 'dumb'}),
    ('consume-records', ['packed-term', 'auto'], {'TERM': 'sun'}),
    ('consume-records', ['packed-term', 'auto'], {'TERM': 'sun-color'}),
    ('consume-records', ['packed-term', 'auto'], {'TERM': 'xterm'}),
    ('consume-records', ['packed-term', 'auto'], {'TERM': None}),
    ('consume-records', ['packed-term', 'utf8'], {'TERM': 'dumb'}),
    ('consume-records', ['packed-term', 'ascii'], {'TERM': 'xterm'}),
    ('consume-records-fault', ['cpu-count-failure'], {}),
    ('consume-records-fault', ['malloc-failures'], {}),
    ('consume-records-fault', ['malloc-failures-oformat'], {}),
    ('consume-records-fault', ['nodev-ustack'], {}),
    ('consume-records-fault', ['nodev-ustack-oformat'], {}),
    ('consume-records-fault', ['nodev-uaddr-256'], {}),
    ('consume-records-fault', ['nodev-uaddr-256-oformat'], {}),
    ('consume-records-fault', ['nodev-more'], {}),
    ('consume-records-fault', ['nodev-more-oformat'], {}),
    ('consume-records-fault', ['nodev-go-enotty'], {}),
    ('consume-records-fault', ['print-xo-allocation'], {}),
]
passed, failed, rcs = [], [], []
xfail, xpass = [], []
text = []
for binary, args, extra in runs:
    local = env.copy()
    for k, v in extra.items():
        if v is None:
            local.pop(k, None)
        else:
            local[k] = v
    test = subprocess.run([str(out / binary), *args], env=local, cwd=out,
        capture_output=True, text=True, timeout=900)
    text.append('$ %s %s %s\n%s%s' % (extra, binary, ' '.join(args), test.stdout, test.stderr))
    rcs.append(test.returncode)
    tag = '' if not args or not args[0].startswith('packed') else \
        '[%s,%s]' % (args[1], extra.get('TERM') or 'unset')
    passed += [l.split()[1] + tag for l in test.stdout.splitlines() if l.startswith('PASS ')]
    # Known failures in files this suite does not own (see the harness).
    xfail += [l[6:] for l in test.stdout.splitlines() if l.startswith('XFAIL ')]
    xpass += [l.split()[1] for l in test.stdout.splitlines() if l.startswith('XPASS ')]
    failed += [l.split()[1].rstrip(':') + tag for l in test.stdout.splitlines()
               if l.startswith('FAIL ')]
    if test.returncode and not any(l.startswith('FAIL ') for l in test.stdout.splitlines()):
        failed.append('%s %s exited %d' % (binary, ' '.join(args), test.returncode))
(out / 'run.log').write_text('\n'.join(text))

# Structured output, parsed and compared with the documented record formats
# (expected values derived in consume-records.c's comments and the model).
def probes(path, strict=True):
    return json.loads((out / path).read_text(), strict=strict)['dtrace']['probes']

def header(cpu, pid, func, name, ts):
    return {'timestamp': ts, 'cpu': cpu, 'id': pid, 'provider': 'test',
            'module': 'kernel', 'function': func, 'name': name}

def tuples(doc):
    """Every aggregation tuple object anywhere in the document."""
    found = []
    def walk(x):
        if isinstance(x, dict):
            if 'keys' in x:
                found.append(x)
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(doc)
    return found

def frame(sym, mod=None, name=None, off=None):
    f = {'symbol': sym}
    if mod is not None:
        f['module'] = mod
    if name is not None:
        f['name'] = name
    if off is not None:
        f['offset'] = off
    return f

def check_records():
    alpha, beta = probes('oformat-records.json')
    out_a = alpha.pop('output')
    out_b = beta.pop('output')
    # The model stamps firings 1000 ns apart.
    assert alpha == header(0, 4, 'alpha', 'entry', 1000), alpha
    assert beta == header(1, 6, 'beta', 'entry', 2000), beta
    typed = out_a.pop()
    want_a = [
        {'stack-frames': [
            frame('kernel`vm_fault+0x10', 'kernel', 'vm_fault', '0x10'),
            frame('kernel`vm_fault', 'kernel', 'vm_fault'),
            frame('zfs`0xffffffff90000400', 'zfs', None, '0xffffffff90000400'),
            frame('0x1234', None, None, '0x1234')]},
        # Vector opens print raw user addresses; '@' strings annotate.
        {'ustack-frames': [
            dict(frame('0x400100', None, None, '0x400100'), annotation='ann'),
            frame('0x400200', None, None, '0x400200'),
            dict(frame('0x400300', None, None, '0x400300'), annotation='b')]},
        {'sym': 'zfs`0xffffffff90000400', 'object': 'zfs',
         'offset': '0xffffffff90000400'},
        {'mod': '0x1234'}, {'usym': '0x401234'}, {'umod': '0x402000'},
        {'usym': 'guest[7]:pid[42]`0x401234'},
        {'printm': 'PRNT'}, {'tracemem': '0123456789abcdefghi'},
        # (char)-3 and (short)-3 print unsigned; 4 and 8 bytes signed.
        {'value': 253}, {'value': 65533}, {'value': -3}, {'value': -3},
        {'value': '0x6162006364'}, {'value': 'ABCDEFGHIJKLMNOPQRST'},
        {'value': 'alpha'},
        # printf: the message, then each consumed record's value; a
        # format that consumes no record ("%%") has no value.
        {'message': '-3\n'}, {'value': -3}, {'message': '100%\n'},
    ]
    assert out_a == want_a, out_a
    types = typed['type']
    assert types[0]['object-name'] == 'D' and types[0]['name'] == 'struct pf'
    members = {t['member-name']: t['value'] for t in types[1:]}
    assert members['a'] == '0x7' and members['b'] == 'xy', members
    assert out_b == [
        {'stack-frames': [
            frame('guest[9]`0xffffffff81000010', 'guest[9]', None,
                  '0xffffffff81000010'),
            frame('guest[9]`0xffffffff81000020', 'guest[9]', None,
                  '0xffffffff81000020')]},
        {'guest-vmid': 7, 'guest-pid': 42,
         'ustack-frames': [frame('0x500100', None, None, '0x500100')]},
        {'usym': 'guest[7]:pid[42]`0x401234'}], out_b

def check_aggregations():
    doc = probes('oformat-aggregations.json')
    printa = doc[0]
    assert printa['name'] == 'return' and printa['function'] == 'beta'
    assert printa['output'] == [{'aggregation-data': [
        {'keys': [{'value': 'beta'}], 'count': 1, 'sum': 5}],
        'aggregation-name': 'c'}], printa['output']
    got = tuples(doc[1:])
    v = lambda x: {'value': x}
    ll = [{'value': 1, 'count': 1, 'operator': '<'}]
    ll += [{'value': x, 'count': 0} for x in list(range(1, 10)) +
           list(range(10, 100, 10))]
    ll += [{'value': 100, 'count': 1, 'operator': '>='}]
    want = [
        {'keys': [v(253), v(65533), v(-3)], 'min': -3},
        {'keys': [v(150), v(150), v(150)], 'min': 150},
        {'keys': [v(253)], 'max': -3}, {'keys': [v(150)], 'max': 150},
        {'keys': [{'ustack-frames': [frame('0x400100', None, None,
                                           '0x400100')]}], 'sum': 147},
        {'keys': [{'usym': '0x401234'}], 'count': 2},
        {'keys': [{'umod': '0x401234'}], 'count': 2},
        {'keys': [{'usym': 'guest[7]:pid[42]`0x401234'}], 'count': 2},
        {'keys': [v('0x6162006364')], 'count': 2},
        {'keys': [], 'buckets': ll},
        {'keys': [], 'buckets': [
            {'value': 0, 'operator': '<', 'count': 1},
            {'value': 0, 'count': 0}, {'value': 5, 'count': 0},
            {'value': 10, 'operator': '>=', 'count': 1}]},
    ]
    canon = lambda x: json.dumps(x, sort_keys=True)
    assert sorted(map(canon, got)) == sorted(map(canon, want)), got

def check_drops(path):
    doc = probes(path)
    assert [p['output'] for p in doc[:2]] == [[{'value': 1}], [{'value': 2}]]
    drop = doc[2]
    assert {k: drop[k] for k in ('cpu', 'id', 'provider', 'module',
            'function', 'name', 'count', 'msg')} == {
        'cpu': 0, 'id': -1, 'provider': 'dtrace', 'module': 'INTERNAL',
        'function': 'INTERNAL', 'name': 'DROP', 'count': 1,
        'msg': '1 drop on CPU 0\n'}, drop
    assert len(doc) == 3

def check_nodev():
    # The harness prints the names libproc must produce for its own pid
    # (from dladdr() and its own symbol), then the document is compared.
    line = [l for l in '\n'.join(text).splitlines() if l.startswith('NODEV ')][0]
    vals = dict(kv.split('=', 1) for kv in line.split()[1:])
    fn, objbase = vals['fn'], vals['base']
    obj = fn.split('`')[0]
    a, b = probes('nodev-ustack.json')
    assert a['output'] == [
        {'ustack-frames': [
            frame(fn + '+0x4', obj, 'cr_ustack_target', '0x4'),
            frame(fn, obj, 'cr_ustack_target'),
            # A helper string is used for writable unmapped-object memory.
            frame('jit'),
            frame('0x10', None, None, '0x10'),
            # Not for read-only object text without a symbol.
            frame(objbase, obj, None, objbase.split('`')[1])]},
        {'usym': fn}, {'umod': obj}, {'umod': '0x10'},
        {'usym': fn + '+0x4'}, {'usym': '0x10'}], a['output']
    # pid 0 cannot be grabbed: raw addresses.
    frames = b['output'][0]['ustack-frames']
    assert len(frames) == 1 and frames[0]['symbol'] == frames[0]['offset']

def check_edges():
    a, b, agg = probes('oformat-edges.json')
    assert a['output'] == [
        # 32-bit frames; a zero PC ends the stack.
        {'stack-frames': [frame('0x1010', None, None, '0x1010'),
                          frame('0x2000', None, None, '0x2000')]},
        {'sym': '0x1234', 'offset': '0x1234'},
        # Eight bytes of helper strings cover two frames only.
        {'ustack-frames': [
            dict(frame('0x400100', None, None, '0x400100'), annotation='a'),
            dict(frame('0x400200', None, None, '0x400200'),
                 annotation='bcde'),
            frame('0x400300', None, None, '0x400300')]},
        # An unknown printf format: the record is plain data.
        {'value': 77}], a['output']
    # A user stack without frames emits nothing in its output object.
    assert b['output'] == [{}], b['output']
    assert agg == {'keys': [{'value': 'beta'}], 'sum': 6}, agg

def check_uaddr256():
    line = [l for l in '\n'.join(text).splitlines()
            if l.startswith('NODEVUADDR ')][0]
    want = line.split(' ', 1)[1]
    assert len(want) == 256
    (p,) = probes('nodev-uaddr.json')
    assert p['output'] == [{'usym': want}], p['output']

def check_more():
    # libxo leaves control characters unescaped inside JSON strings (the
    # consumer treats tab, backspace and bell as printable); parse leniently.
    doc = probes('oformat-more.json', strict=False)
    rec = doc[0]['output']
    js = {'ustack-frames': [frame('0x400100', None, None, '0x400100')]}
    assert rec == [{'value': 'a\tb\b\x07c'}, {'value': '0x00616200000000000000'},
                   {'value': '0x617f8062000000000000'}, js], rec
    canon = lambda x: json.dumps(x, sort_keys=True)
    want = [
        {'keys': [js], 'count': 1},
        # llquantize(x, 10, 0, 2, 10) of 50: buckets 40, 50, 60 only.
        {'keys': [], 'buckets': [{'value': 40, 'count': 0},
                                 {'value': 50, 'count': 1},
                                 {'value': 60, 'count': 0}]},
        # llquantize(x, 2, 0, 4, 4) of 5: widths 1, 1, 1, 2, ...
        {'keys': [], 'buckets': [{'value': 3, 'count': 0},
                                 {'value': 4, 'count': 1},
                                 {'value': 6, 'count': 0}]},
        {'keys': [], 'average': 0}, {'keys': [], 'stddev': 0}]
    assert sorted(map(canon, tuples(doc[1:]))) == sorted(map(canon, want))

def check_nodev_more():
    line = [l for l in '\n'.join(text).splitlines()
            if l.startswith('NODEVLONG ')][0]
    want = line.split(' ', 1)[1]
    (p,) = probes('nodev-more.json')
    assert p['output'] == [
        {'ustack-frames': [frame('unm')]},
        {'guest-vmid': 7, 'guest-pid': 42,
         'ustack-frames': [frame('0x500100', None, None, '0x500100')]},
        {'usym': '0x401234'}, {'usym': want}], p['output']

for case, fn in (('oformat-records', check_records),
                 ('oformat-more', check_more),
                 ('nodev-more-oformat', check_nodev_more),
                 ('nodev-uaddr-256-oformat', check_uaddr256),
                 ('oformat-edges', check_edges),
                 ('nodev-ustack-oformat', check_nodev),
                 ('oformat-aggregation-tuples', check_aggregations),
                 ('oformat-drops', lambda: check_drops('oformat-drops.json')),
                 ('oformat-drops-temporal',
                  lambda: check_drops('oformat-drops-temporal.json'))):
    try:
        fn()
        passed.append(case)
    except (OSError, ValueError, KeyError, TypeError, IndexError,
            AssertionError) as error:
        failed.append(case)
        text.append('%s: %r' % (case, error))
        (out / 'run.log').write_text('\n'.join(text))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p)
    for p in (library, *sources)},
    'scope': 'dtrace_vopen with the consume-ingestion dtrace(4) model; scripted '
    'firings; no device, kernel, DIF execution, guest or daemon'}, indent=2) + '\n')
(out / 'results.json').write_text(json.dumps({'returncodes': rcs,
    'passed': passed, 'failed': failed, 'known_failures': xfail,
    'unexpected_passes': xpass}, indent=2) + '\n')
if any(rcs) or failed or not passed:
    print('\n'.join(text)[-6000:])
    raise SystemExit('consume records failed; inspect run.log')
print('PASS:', len(passed), 'consumer record cases;', len(xfail),
      'known failures outside this suite\'s files', *xfail, sep=' ')
