# SPDX-License-Identifier: BSD-2-Clause
"""Shared driver for the frontend-parser-*.py suites.

Builds frontend-parser.c against the library under test with libdtrace's own
include/define flags and runs batches of D compile cases through it.  The
harness only reports what libdtrace produced; every suite supplies its own
independent oracle.  Also parses the DIF ISA constants from the system
header (sys/dtrace.h), never from libdtrace sources.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
TESTS = ROOT / 'contrib/hypertrace/tests'
HDR = ROOT / 'sys/cddl/contrib/opensolaris/uts/common/sys/dtrace.h'
ETAGS, EMPTY, ZDEFS, EATTR = 0x100, 0x2, 0x4, 0x8
SUGAR, DEFARG, NOLIBS, CTL, ARGREF, PSPEC = 0x400, 0x800, 0x1000, 0x2000, 0x200, 0x80
KNODEF, UNODEF, DIFV = 0x20, 0x40, 0x1


def dif_constants():
    """DIF_OP_*, DIF_VAR_*, DIF_TYPE_* and DTRACEACT_* from sys/dtrace.h."""
    text = HDR.read_text()
    consts = {}
    for name, value in re.findall(r'#define\s+(DIF_[A-Z0-9_]+|DTRACEACT_[A-Z0-9_]+)\s+'
                                  r'(0x[0-9a-fA-F]+|\d+)\b', text):
        consts.setdefault(name, int(value, 0))
    # DTRACEACT_* kinds are built from class bases: resolve simple sums.
    for name, base, off in re.findall(
            r'#define\s+(DTRACEACT_[A-Z0-9_]+|DTRACEAGG_[A-Z0-9_]+)\s+\((DTRACEACT_[A-Z_]+)\s*\+\s*(\d+)\)', text):
        if base in consts:
            consts[name] = consts[base] + int(off)
    return consts


class Harness:
    def __init__(self, out, obj):
        self.out = out = Path(out).resolve()
        self.obj = obj
        self.lib = obj / 'cddl/lib/libdtrace'
        self.library = self.lib / 'libdtrace.so.2'
        prefix = Path(*obj.parts[:obj.parts.index('usr', 3)])
        cflags = subprocess.run(
            ['make', '-C', str(ROOT / 'cddl/lib/libdtrace'), '-m', str(ROOT / 'share/mk'),
             'SRCTOP=' + str(ROOT), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
             '-V', 'CFLAGS'], env=os.environ | {'MAKEOBJDIRPREFIX': str(prefix)},
            capture_output=True, text=True, check=True).stdout.split()
        keep = [f for f in cflags if f.startswith(('-I', '-D', '-std='))]
        self.source = TESTS / 'frontend-parser.c'
        self.binary = out / 'frontend-parser'
        cmd = ['cc', *keep, '-g', '-O1', '-fsanitize=address,undefined',
               '-fno-sanitize-recover=undefined', '-Wall', '-Wno-unknown-pragmas',
               str(self.source), '-L' + str(self.lib), '-Wl,-rpath,' + str(self.lib),
               '-ldtrace', '-lctf', '-lelf', '-o', str(self.binary)]
        b = subprocess.run(cmd, capture_output=True, text=True)
        (out / 'build.log').write_text(' '.join(cmd) + '\n' + b.stdout + b.stderr)
        if b.returncode:
            raise SystemExit('harness compilation failed; inspect build.log')
        self.env = os.environ.copy()
        self.env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in
            ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
        self.env['ASAN_OPTIONS'] = 'detect_leaks=0'
        self.env['UBSAN_OPTIONS'] = 'print_stacktrace=1:halt_on_error=1'
        self.batch = 0

    def run(self, cases, extra_env=None):
        """cases: list of dicts with id, src, and optional mode, flags, oflags,
        args, opts, keep, nosrc.  Returns {id: result}."""
        self.batch += 1
        inp = self.out / f'batch{self.batch}.in'
        res = self.out / f'batch{self.batch}.jsonl'
        with inp.open('wb') as f:
            for c in cases:
                f.write(f"@case {c['id']}\n".encode())
                f.write(f"@mode {c.get('mode', 'prog')}\n".encode())
                f.write(f"@flags {c.get('flags', ETAGS):x}\n".encode())
                if 'oflags' in c:
                    f.write(f"@oflags {c['oflags']:x}\n".encode())
                if c.get('keep'):
                    f.write(b'@keep\n')
                if c.get('nosrc'):
                    f.write(b'@nosrc\n')
                if c.get('dof'):
                    f.write(b'@dof\n')
                for a in c.get('args', []):
                    f.write(b'@arg ' + a.encode() + b'\n')
                for o in c.get('opts', []):
                    f.write(b'@opt ' + o.encode() + b'\n')
                for m in c.get('elfmods', []):
                    f.write(b'@elfmod ' + m.encode() + b'\n')
                for m in c.get('modules', []):
                    f.write(b'@module ' + m.encode() + b'\n')
                src = c.get('src', '').encode()
                f.write(f'@src {len(src)}\n'.encode() + src + b'\n@end\n')
        env = self.env | (extra_env or {})
        r = subprocess.run([str(self.binary), str(inp), str(res)], cwd=self.out,
                           env=env, capture_output=True, text=True, timeout=3600)
        (self.out / f'batch{self.batch}.log').write_text(r.stdout + r.stderr)
        if r.returncode:
            raise SystemExit(f'harness batch {self.batch} exited {r.returncode}; '
                             f'see batch{self.batch}.log')
        results = {}
        for line in res.read_text().splitlines():
            d = json.loads(line)
            results[d['id']] = d
        return results

    def provenance(self, scripts, scope):
        sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
        files = [self.library, self.source, Path(__file__).resolve(), *map(Path, scripts)]
        (self.out / 'provenance.json').write_text(json.dumps(
            {'sha256': {str(p): sha(p) for p in files}, 'scope': scope}, indent=2) + '\n')


def tag(result):
    m = re.match(r'\[(D_[A-Z0-9_]+)\]', result.get('error') or '')
    return m.group(1) if m else None


def check_args(argv, usage):
    from pathlib import Path as P
    if len(argv) != 3:
        raise SystemExit(usage)
    out, obj = (P(a).resolve() for a in argv[1:])
    if not all(p.is_relative_to('/usr/obj') for p in (out, obj)) or out.exists():
        raise SystemExit('Use a new /usr/obj output directory and an existing object tree')
    if obj.name == 'libdtrace.so.2':
        raise SystemExit('pass the instrumented world directory (amd64.amd64)')
    out.mkdir(parents=True)
    return out, obj
