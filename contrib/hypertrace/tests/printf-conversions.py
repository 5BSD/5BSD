#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""printf()/printa()/print() formatting through the actual libdtrace, offline.

Builds printf-conversions.c (which includes the dtrace(4) model of
consume-ingestion.c) with libdtrace's compile flags and ASan/UBSan, and the
preloaded resolver stand-in printf-conversions-shim.c.  Before trusting the
stand-in, the FreeBSD libc return conventions it imitates are checked against
the real getservbyport_r()/gethostbyaddr_r() with entries every installation
carries in files (port 22, 127.0.0.1), so no network lookup happens.  The
structured print() output is checked here as parsed JSON against the CTF
layout the harness records.  No device, kernel, daemon or network is used.

usage: printf-conversions.py /usr/obj/new-output /usr/obj/.../amd64.amd64
"""
from pathlib import Path
import hashlib
import json
import os
import struct
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit(__doc__.strip().splitlines()[-1])
root = Path(__file__).resolve().parents[3]
out, obj = (Path(a).resolve() for a in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out, obj)) or out.exists():
    raise SystemExit('Use a new /usr/obj output directory and an existing object tree')
out.mkdir(parents=True)
tests = root / 'contrib/hypertrace/tests'
lib = obj / 'cddl/lib/libdtrace'
library = lib / 'libdtrace.so.2'
prefix = Path(*obj.parts[:obj.parts.index('usr', 3)]) if 'usr' in obj.parts[3:] else obj
cflags = subprocess.run(
    ['make', '-C', str(root / 'cddl/lib/libdtrace'), '-m', str(root / 'share/mk'),
     'SRCTOP=' + str(root), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null', '-V', 'CFLAGS'],
    env=os.environ | {'MAKEOBJDIRPREFIX': str(prefix)}, capture_output=True, text=True,
    check=True).stdout.split()
keep = [f for f in cflags if f.startswith(('-I', '-D', '-std='))]
includes = [prefix / 'source-includes'] if (prefix / 'source-includes').exists() else []
source = tests / 'printf-conversions.c'
shim_src = tests / 'printf-conversions-shim.c'
model = tests / 'consume-ingestion.c'


def build(cmd, log):
    r = subprocess.run(cmd, capture_output=True, text=True)
    (out / log).write_text(' '.join(map(str, cmd)) + '\n' + r.stdout + r.stderr)
    if r.returncode:
        raise SystemExit('compilation failed; inspect ' + log)


# The libc conventions the shim imitates, from the real resolver (files only).
probe = out / 'libc-conventions.c'
probe.write_text(r'''
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
int main(void) {
    struct servent res, *sv = (void *)1; struct hostent h, *hp = (void *)1;
    char buf[1024], a[4]; int e, r1, r2, r3, r4;
    r1 = getservbyport_r(htons(22), NULL, &res, buf, sizeof buf, &sv);
    printf("serv-found %d %d\n", r1, sv != NULL);
    r2 = getservbyport_r(htons(22), NULL, &res, buf, 4, &sv);
    printf("serv-erange %d %d\n", r2, sv != NULL);
    inet_pton(AF_INET, "127.0.0.1", a);
    r3 = gethostbyaddr_r(a, 4, AF_INET, &h, buf, sizeof buf, &hp, &e);
    printf("host-found %d %d\n", r3, hp != NULL);
    r4 = gethostbyaddr_r(a, 4, AF_INET, &h, buf, 8, &hp, &e);
    printf("host-erange %d %d\n", r4, hp != NULL);
    return 0;
}
''')
build(['cc', '-o', str(out / 'libc-conventions'), str(probe)], 'libc-conventions.log')
conv = subprocess.run([str(out / 'libc-conventions')], capture_output=True, text=True,
                      timeout=60).stdout.split('\n')
conventions_ok = conv[:4] == ['serv-found 0 1', 'serv-erange 34 0', 'host-found 0 1',
                              'host-erange 34 0']

build(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror', str(shim_src), '-o',
       str(out / 'printf-conversions-shim.so')], 'shim-build.log')
build(['cc', *keep, *('-I' + str(p) for p in includes), '-I' + str(tests),
       '-I' + str(root / 'cddl/contrib/opensolaris/common/ctf'),
       '-g', '-O1', '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined',
       '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unknown-pragmas',
       '-Wno-unused-parameter', '-Wno-sign-compare', '-Wno-missing-field-initializers',
       str(source), '-L' + str(lib), '-L' + str(obj / 'cddl/lib/libctf'),
       '-ldtrace', '-lctf', '-lelf', '-lxo', '-o', str(out / 'printf-conversions')],
      'build.log')
env = os.environ.copy()
env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in
    ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
env['LD_PRELOAD'] = str(out / 'printf-conversions-shim.so')
env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=0'
env['UBSAN_OPTIONS'] = 'print_stacktrace=1:halt_on_error=1'
test = subprocess.run([str(out / 'printf-conversions'), str(out)], env=env, cwd=out,
                      capture_output=True, text=True, timeout=600)
(out / 'run.log').write_text(test.stdout + test.stderr)
lines = test.stdout.splitlines()
passed = [l.split()[1] for l in lines if l.startswith('PASS ')]
failed = [l.split()[1].rstrip(':') for l in lines if l.startswith('FAIL ')]
xfail = [l for l in lines if l.startswith('XFAIL ')]
xpass = [l.split()[1] for l in lines if l.startswith('XPASS ')]
if not conventions_ok:
    failed.append('libc-conventions')
else:
    passed.append('libc-conventions')

# Structured print(): values decoded from the raw bytes at the CTF offsets,
# formatted by dt_print.c's rules (%#x integers, quoted printable chars, the
# NUL character as "0", strings for NUL-terminated char arrays).
checks = {}
try:
    doc = json.loads((out / 'format-print.json').read_text())
    raw = (out / 'format-print.raw').read_bytes()
    lay = json.loads((out / 'format-print-layout.json').read_text())
    cases = {c['case']: c for c in doc['format-print']['cases']}

    def hx(v):
        return '0' if v == 0 else hex(v)

    def le(off, n):
        return int.from_bytes(raw[off:off + n], 'little')

    def members(case):
        return {t['member-name']: t for t in cases[case]['type'] if 'member-name' in t}

    m = members('ints')
    L = {k: v // 8 for k, v in lay['ints'].items()}
    top = cases['ints']['type'][0]
    checks['format-print-ints'] = (
        top == {'object-name': 'C', 'name': 'struct pt_ints', 'ctfid': cases['ints']['ctfid']} and
        [t.get('member-name') for t in cases['ints']['type'][1:]] ==
        ['a', 'b', 'c', 'd', 'e', 'f', 'z', 'g', 't', 'c16', 'small', 'h100'] and
        m['c16']['value'] == hx(le(L['c16'], 2)) and
        m['small']['value'] == hx(le(L['small'], 16)) and
        m['h100'].get('warning') == 'unsupported bit-field width' and
        m['a']['value'] == hx(raw[L['a']]) and m['b']['value'] == hx(le(L['b'], 2)) and
        m['c']['value'] == hx(le(L['c'], 4)) and m['d']['value'] == hx(le(L['d'], 8)) and
        m['e']['value'] == hx(le(L['e'], 3)) and m['f']['value'] == hx(le(L['f'], 16)) and
        m['z']['value'] == hx(le(L['z'], 16)) and 'value' not in m['g'] and
        m['t']['name'] == 'pt_td_t' and m['t']['value'] == hx(le(L['t'], 4)))
    m = members('chars')
    L = {k: v // 8 for k, v in lay['chars'].items()}

    def ch(b):
        return '0' if b == 0 else chr(b) if 0x20 <= b < 0x7f else oct(b)
    checks['format-print-chars'] = all(
        (m[k]['value'] == ch(raw[L[k]]) or m[k]['value'] == int(oct(raw[L[k]])[2:]))
        for k in ('p', 'z', 'np')) and m['u']['value'] == hx(raw[L['u']])
    m = members('fp')
    L = {k: v // 8 for k, v in lay['fp'].items()}
    f = struct.unpack_from('<f', raw, L['f'])[0]
    d = struct.unpack_from('<d', raw, L['d'])[0]
    checks['format-print-floats'] = (
        isinstance(m['f']['value'], float) and m['f']['value'] == float('%.7e' % f) and
        isinstance(m['d']['value'], float) and m['d']['value'] == float('%.7e' % d) and
        m['c'].get('warning') == 'unknown encoding' and 'value' not in m['c'])
    m = members('struct')
    L = {k: v // 8 for k, v in lay['struct'].items()}
    name_bytes = raw[L['name']:L['name'] + 6]
    want_name = name_bytes.split(b'\0')[0].decode() if b'\0' in name_bytes else None
    checks['format-print-arrays'] = (
        m['name']['value'] == want_name and
        [e['value'] for e in m['v']['value']] == [hx(le(L['v'] + 4 * i, 4)) for i in range(3)] and
        m['p']['value'] == hx(le(L['p'], 8)))
    # A top-level array or invalid type is described by the first instance.
    a2 = cases['arr2']['type'][0]['value']
    checks['format-print-2d'] = [[e['value'] for e in row['value']] for row in a2] == \
        [[hx(le(12 * r + 4 * c, 4)) for c in range(3)] for r in range(2)]
    checks['format-print-strings'] = (cases['str6']['type'][0]['value'] == 'hi' and
                                     cases['nonstr']['type'][0]['value'] == 'hi')
    checks['format-print-forward'] = (
        cases['fwd']['type'][1:] == [] and
        [e['name'] for e in cases['fwdarr']['type'][0]['value']] == ['struct pt_fwd'] * 2)
    bad = cases['badarr']['type'][0]
    checks['format-print-invalid-element'] = (
        bad.get('warning') == 'invalid type' and bad.get('type-identifier') == 0x7ffe)
    m = members('badmem')
    checks['format-print-invalid-member'] = (
        m['ok']['value'] == hx(le(lay['badmem']['ok'] // 8, 4)) and
        m['bad'] == {'member-name': 'bad', 'warning': 'invalid type',
                     'type-identifier': lay['unknown_id']})
    checks['format-print-unknown-toplevel'] = cases['unknown']['type'] == [
        {'warning': 'invalid type', 'type-identifier': lay['unknown_id']}]
    m = members('bits')
    lo64 = le(0, 8)
    want_bits = {k: (int.from_bytes(raw[:16], 'little') >> off) & ((1 << w) - 1)
                 for (k, off), w in zip(lay['bits'].items(), (3, 5, 24, 8, 12, 128))}
    checks['format-print-bitfields'] = all(
        m[k]['value'] == hx(want_bits[k]) for k in ('lo', 'hi', 'w', 'sh', 'sp')) and \
        m['wide'].get('warning') == 'unsupported bit-field width' and lo64 >= 0
except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
    checks['format-print-json'] = False
    print('format-print.json:', repr(error))

# print() through the model: struct pm from D, values as the harness fired.
try:
    doc = json.loads((out / 'print-model.json').read_text())
    types = doc['dtrace']['probes'][0]['output'][0]['type']
    top, rest = types[0], {t['member-name']: t for t in types[1:]}
    checks['print-model-structure'] = (
        top['object-name'] == 'D' and top['name'] == 'struct pm' and top['ctfid'] >= 0 and
        rest['a']['value'] == hex((-2) & 0xffffffff) and rest['s']['value'] == 'json' and
        [e['value'] for e in rest['v']['value']] == ['0x3', '0x4'] and
        rest['lo']['value'] == '0x5' and rest['hi']['value'] == '0x9' and
        rest['e']['value'] == 'PM_B' and
        [e['value'] for e in rest['np']['value']][0] == 'a')
except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
    checks['print-model-structure'] = False
    print('print-model.json:', repr(error))

for name, ok in checks.items():
    (passed if ok else failed).append(name)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p) for p in
    (library, source, shim_src, model, Path(__file__).resolve())},
    'scope': 'dtrace_vopen with the consume-ingestion dtrace(4) model and dtrace_open '
             'NODEV; preloaded resolver stand-in; no device, kernel, daemon or network'},
    indent=2) + '\n')
(out / 'results.json').write_text(json.dumps({'returncode': test.returncode,
    'passed': passed, 'failed': failed, 'known_external_failures': xfail,
    'unexpected_passes': xpass, 'json_checks': checks}, indent=2) + '\n')
for line in xfail:
    print(line)
if test.returncode or failed or not passed:
    print(test.stdout[-4000:], test.stderr[-4000:])
    print('failed:', failed)
    raise SystemExit('printf conversions failed; inspect run.log')
print('PASS:', len(passed), 'printf/printa/print formatting cases')
