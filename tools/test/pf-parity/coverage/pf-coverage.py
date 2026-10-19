#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Live function coverage of OpenBSD PF on 5BSD, measured with DTrace.

  pf-coverage.py run   HOST OUT.json [--skip A.json,B.json] SUITE...
                                                run kyua SUITEs on HOST under
                                                DTrace fbt and save the counts
                                                (--skip: no probes on functions
                                                these runs saw; merge them)
  pf-coverage.py boot  HOST OUT.json            count the functions run while
                                                HOST boots (anonymous DTrace:
                                                pf.ko's load and attach code)
  pf-coverage.py merge OUT.json IN.json...      union of several runs
  pf-coverage.py report COV.json [--md FILE]    covered/uncovered per file

The function universe is every function defined in pf.ko's objects (glue in
sys/netpfil/openbsd-pf and vendor code in contrib/openbsd-pf) and in the
FreeBSD stack files land/pf changed (STACK_OBJS), read from the build's
object files with nm(1).  fbt has no probe for inlined functions; those
are reported as "no probe" when DTrace lists no probe for them.
"""
import json
import os
import re
import subprocess
import sys
import time

SSH = ['ssh', '-F', '/usr/obj/5BSD-pf-parity/keys/ssh_config',
       '-o', 'ConnectTimeout=300']
OBJ = '/usr/obj/usr/obj/5BSD-pf-land/amd64.amd64/sys/GENERIC'
# PFCOV_OBJ: the objects of the pf.ko under test, built with
# DEBUG_FLAGS='-g -fno-inline -fno-inline-functions -mllvm
# -enable-shrink-wrap=false' so that fbt sees every function: without
# -fno-inline the compiler inlines small ones, and with shrink-wrapping
# clang moves a leaf function's frame setup off its entry, where fbt's
# entry probe then never fires (one function in ten in pf.c; they were
# reported as not run although they ran).
PFOBJ = os.environ.get('PFCOV_OBJ',
                       OBJ + '/modules/usr/obj/5BSD-pf-land/sys/modules/pf')
# Kernel (not module) objects whose functions land/pf added or changed.
STACK_OBJS = ['if_egress.o', 'in.o', 'in6.o', 'if.o', 'if_vlan.o',
              'if_ethersubr.o', 'route_rdomain.o', 'ip_carp.o', 'uipc_domain.o',
              'ip_fastfwd.o', 'ip6_fastfwd.o', 'in_pcb.o', 'ip_output.o',
              'ip6_output.o', 'tcp_subr.o', 'if_loop.o']
GLUE = {'openbsd_compat', 'openbsd_ifq', 'openbsd_net', 'pf_divert',
        'pf_dummynet', 'pf_ether', 'pf_freebsd', 'pf_jail', 'pf_pfsync',
        'pf_quota', 'pf_sctp', 'pf_sdt', 'pf_sysctl'}


def sh(host, cmd, **kw):
    return subprocess.run(SSH + [host, cmd], text=True, **kw)


def universe():
    funcs = {}
    def add(path, module):
        out = subprocess.run(['nm', '--defined-only', path], text=True,
                             capture_output=True).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] in 'tT':
                name = parts[2]
                if name.startswith(('.L', '__', 'sysctl_')) and \
                        '.' in name:
                    continue
                name = name.split('.')[0]	# .cold, .isra clones
                base = os.path.basename(path)[:-2]
                funcs.setdefault((module, name), base)
    for f in sorted(os.listdir(PFOBJ)):
        if f.endswith('.o') and f != 'genoffset.o':
            add(os.path.join(PFOBJ, f), 'pf')
    for f in STACK_OBJS:
        p = os.path.join(OBJ, f)
        if os.path.exists(p):
            add(p, 'kernel')
    return funcs


def dtrace_alive(host):
    """Stop with dtrace's own messages if it is not running."""
    if sh(host, 'test -s /root/pfcov.pid && '
          'kill -0 $(cat /root/pfcov.pid)').returncode != 0:
        log = sh(host, 'cat /root/pfcov.dtrace.log',
                 capture_output=True).stdout
        sys.exit('dtrace is not running on %s; its log:\n%s' % (host, log))


def run(host, out, suites, skip=None):
    funcs = universe()
    kfuncs = sorted({n for (m, n) in funcs if m == 'kernel'})
    if skip:
        # Probe only what earlier runs did not see: the functions they saw
        # include the hot ones, whose probes make an emulated guest crawl.
        kfuncs = [n for n in kfuncs if 'kernel:' + n not in skip]
        pfuncs = sorted({n for (m, n) in funcs
                         if m == 'pf' and 'pf:' + n not in skip})
        clauses = []
        for i in range(0, len(pfuncs), 50):
            probes = ','.join('fbt:pf:%s:entry' % n
                              for n in pfuncs[i:i + 50])
            clauses.append(probes + ' { @c["pf", probefunc] = count(); }')
    else:
        # One clause for pf.ko, one per kernel function.
        clauses = ['fbt:pf::entry { @c["pf", probefunc] = count(); }']
    for i in range(0, len(kfuncs), 50):
        probes = ','.join('fbt:kernel:%s:entry' % n for n in kfuncs[i:i + 50])
        clauses.append(probes + ' { @c["kernel", probefunc] = count(); }')
    script = '\n'.join(clauses) + '\n'
    sh(host, 'cat > /root/pfcov.d', input=script, check=True)
    # Probes that exist (to tell "not run" from "no probe").
    probes = sh(host, "dtrace -l -m pf -n 'fbt:pf::entry' 2>/dev/null | "
                "awk 'NR>1{print $4}'; dtrace -l -n 'fbt:kernel::entry' "
                "2>/dev/null | awk 'NR>1{print $4}'",
                capture_output=True).stdout.split()
    # kyua refuses an existing results file; daemon -o appends to its log.
    sh(host, 'rm -f /root/pfcov.out /root/pfcov.done /root/pfcov.db '
       '/root/pfcov.kyua.log /root/pfcov.dtrace.log; daemon -f -o '
       '/root/pfcov.dtrace.log -p /root/pfcov.pid dtrace -Z -q '
       '-x aggsize=8m -x dynvarsize=8m -s /root/pfcov.d -o /root/pfcov.out',
       check=True)
    time.sleep(20)
    # A dtrace that did not start (or died) records nothing: a whole run
    # would end with an empty count file that reads as "nothing ran".
    dtrace_alive(host)
    t0 = time.time()
    sh(host, 'daemon -f -o /root/pfcov.kyua.log sh -c "kyua test -r '
       '/root/pfcov.db -k /usr/tests/Kyuafile %s; touch /root/pfcov.done"'
       % ' '.join(suites), check=True)
    while sh(host, 'test -f /root/pfcov.done').returncode != 0:
        time.sleep(120)
    dtrace_alive(host)
    sh(host, 'kill -INT $(cat /root/pfcov.pid); sleep 10')
    raw = sh(host, 'cat /root/pfcov.out', capture_output=True).stdout
    counts = {}
    for line in raw.splitlines():
        m = re.match(r'\s*(pf|kernel)\s+(\S+)\s+(\d+)\s*$', line)
        if m:
            counts['%s:%s' % (m.group(1), m.group(2))] = int(m.group(3))
    report = sh(host, 'kyua report -r /root/pfcov.db --results-filter= | '
                'tail -3', capture_output=True).stdout
    json.dump({'suites': suites, 'seconds': int(time.time() - t0),
               'kyua': report.strip(), 'probes': sorted(set(probes)),
               'counts': counts}, open(out, 'w'), indent=1)
    print('saved %s: %d functions hit' % (out, len(counts)))


def boot(host, out):
    """Functions pf runs while it loads, before a consumer can attach."""
    sh(host, "dtrace -A -q -n 'fbt:pf::entry { @c[\"pf\", probefunc] = "
       "count(); }' >/dev/null && shutdown -r now", check=False)
    time.sleep(90)
    while sh(host, 'true').returncode != 0:
        time.sleep(30)
    raw = sh(host, 'dtrace -a -q -e 2>/dev/null; rm -f /boot/dtrace.dof',
             capture_output=True).stdout
    counts = {}
    for line in raw.splitlines():
        m = re.match(r'\s*(pf|kernel)\s+(\S+)\s+(\d+)\s*$', line)
        if m:
            counts['%s:%s' % (m.group(1), m.group(2))] = int(m.group(3))
    json.dump({'suites': ['boot'], 'seconds': 0, 'kyua': '', 'probes': [],
               'counts': counts}, open(out, 'w'), indent=1)
    print('saved %s: %d functions run at boot' % (out, len(counts)))


def merge(out, ins):
    total = {'suites': [], 'probes': set(), 'counts': {}, 'kyua': []}
    for p in ins:
        d = json.load(open(p))
        total['suites'] += d['suites']
        total['probes'] |= set(d['probes'])
        total['kyua'].append(d.get('kyua', ''))
        for k, v in d['counts'].items():
            total['counts'][k] = total['counts'].get(k, 0) + v
    total['probes'] = sorted(total['probes'])
    json.dump(total, open(out, 'w'), indent=1)
    print('merged %d runs: %d functions hit' % (len(ins), len(total['counts'])))


SRC = '/usr/obj/5BSD-pf-land'
# land/pf's base on dev: stack functions changed since then are pf's scope.
BASE = 'dev'


def changed_stack_funcs():
    """Names of functions in the stack sources that land/pf changed."""
    base = subprocess.run(['git', '-C', SRC, 'merge-base', 'HEAD', BASE],
                          text=True, capture_output=True).stdout.strip()
    names = set()
    for o in STACK_OBJS:
        src = subprocess.run(['git', '-C', SRC, 'ls-files', '--',
                              'sys/*/%s.c' % o[:-2], 'sys/*/*/%s.c' % o[:-2]],
                             text=True, capture_output=True).stdout.split()
        for path in src:
            diff = subprocess.run(['git', '-C', SRC, 'diff', '-U0', base,
                                   'HEAD', '--', path], text=True,
                                  capture_output=True).stdout
            changed = []
            for m in re.finditer(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@',
                                 diff, re.M):
                start, n = int(m.group(1)), int(m.group(2) or 1)
                changed.append((start, start + max(n, 1) - 1))
            if not changed:
                continue
            # Function bodies in style(9): name( at column 0 ... } at column 0.
            text = open(os.path.join(SRC, path)).read().split('\n')
            func, begin = None, 0
            for i, line in enumerate(text, 1):
                m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\(', line)
                if m:
                    func, begin = m.group(1), i
                elif line.startswith('}') and func:
                    if any(a <= i and b >= begin for a, b in changed):
                        names.add(func)
                    func = None
    return names


# Functions RB_GENERATE() emits, and the tree macros that reach each.
RB_OPS = {
    'INSERT': ['INSERT', 'INSERT_NEXT', 'INSERT_PREV'],
    'INSERT_COLOR': ['INSERT', 'INSERT_NEXT', 'INSERT_PREV'],
    'INSERT_FINISH': ['INSERT', 'INSERT_NEXT', 'INSERT_PREV'],
    'INSERT_NEXT': ['INSERT_NEXT'], 'INSERT_PREV': ['INSERT_PREV'],
    'REMOVE': ['REMOVE', 'REINSERT'], 'REMOVE_COLOR': ['REMOVE', 'REINSERT'],
    'REINSERT': ['REINSERT'], 'FIND': ['FIND'], 'NFIND': ['NFIND'],
    'MINMAX': ['MIN', 'MAX', 'ROOT', 'FOREACH', 'FOREACH_SAFE',
               'FOREACH_REVERSE', 'FOREACH_REVERSE_SAFE'],
    'NEXT': ['NEXT', 'FOREACH', 'FOREACH_SAFE', 'FOREACH_FROM'],
    'PREV': ['PREV', 'FOREACH_REVERSE', 'FOREACH_REVERSE_SAFE',
             'FOREACH_REVERSE_FROM'],
}


def rb_unreachable(names):
    """Generated tree functions whose operation pf's source never uses."""
    out = subprocess.run(['grep', '-rhoE',
                          r'\bRBT?_[A-Z_]+\([ ]*[a-z_0-9]+([ ]*,[ ]*[a-z_0-9]+)?',
                          os.path.join(SRC, 'contrib/openbsd-pf/sys'),
                          os.path.join(SRC, 'sys/netpfil/openbsd-pf')],
                         text=True, capture_output=True).stdout
    used = set()
    for m in re.finditer(r'RBT?_([A-Z_]+)\( *([a-z_0-9]+)(?: *, *([a-z_0-9]+))?',
                         out):
        op = m.group(1)
        # RB_FOREACH*(var, name, head): the tree is the second argument.
        tree = m.group(3) if op.startswith('FOREACH') else m.group(2)
        if tree:
            used.add((tree, op))
    dead = set()
    for n in names:
        m = re.match(r'^(.*)_RB_([A-Z_]+)$', n)
        if not m or m.group(2) not in RB_OPS:
            continue
        tree, op = m.group(1), m.group(2)
        if not any((tree, u) in used for u in RB_OPS[op]):
            dead.add(n)
    return dead


DECL = re.compile(r'^\s*(static\s+|extern\s+|__inline\s+|inline\s+)*'
                  r'(void|int|struct|u_int\w*|uint\w*|u_short|u_char|const|'
                  r'char|size_t|caddr_t|sa_family_t|bool|unsigned|long|'
                  r'u_int8_t|u_int16_t|u_int32_t|u_int64_t)\b')


def no_caller(names):
    """pf.ko functions whose name pf's source mentions only where it
    defines or declares them: dead code no test can run.  Any other
    mention (a call, a function pointer, a comment) keeps a function in
    the scope, so this errs towards counting it."""
    text = []
    for top in ('contrib/openbsd-pf/sys', 'sys/netpfil/openbsd-pf'):
        for d, _, fs in os.walk(os.path.join(SRC, top)):
            for f in fs:
                if f.endswith(('.c', '.h')):
                    text.append(open(os.path.join(d, f),
                                     errors='replace').read())
    lines = '\n'.join(text).split('\n')
    out = set()
    for n in names:
        # Only functions pf's source defines; generated tree functions are
        # used through macros (rb_unreachable() covers them), inlines from
        # kernel headers are not pf's code.
        if '_RB_' in n or not any(re.match(r'^%s\s*\(' % re.escape(n), l)
                                  for l in lines):
            continue
        w = re.compile(r'\b%s\b' % re.escape(n))
        refs = 0
        for line in lines:
            if not w.search(line):
                continue
            if re.match(r'^%s\s*\(' % re.escape(n), line):
                continue		# the definition
            if re.match(r'^\s*#\s*define\s+%s\b' % re.escape(n), line):
                continue
            if DECL.match(line) and re.search(r'\b%s\s*\(' % re.escape(n),
                                              line):
                continue		# a prototype
            refs += 1
            break
        if refs == 0:
            out.add(n)
    return out


def report(cov, md=None):
    d = json.load(open(cov))
    funcs = universe()
    probes = set(d['probes'])
    hit = d['counts']
    files = {}
    for (module, name), base in funcs.items():
        key = '%s:%s' % (module, name)
        f = files.setdefault((module, base), {'hit': [], 'miss': [],
                                              'noprobe': []})
        if hit.get(key):
            f['hit'].append(name)
        elif name not in probes:
            f['noprobe'].append(name)
        else:
            f['miss'].append(name)
    lines = ['| file | kind | functions | hit | % | not run |', '|---|---|---|---|---|---|']
    th = tm = 0
    for (module, base), f in sorted(files.items()):
        n = len(f['hit']) + len(f['miss'])
        if n == 0:
            continue
        kind = 'glue' if base in GLUE else ('vendor' if module == 'pf' else 'stack')
        th += len(f['hit'])
        tm += len(f['miss'])
        lines.append('| %s | %s | %d | %d | %d | %s |' % (
            base, kind, n, len(f['hit']), 100 * len(f['hit']) // n,
            ', '.join(sorted(f['miss']))))
    lines.append('')
    # The goal's scope: all of pf.ko, and the stack functions land/pf changed.
    scoped = changed_stack_funcs()
    dead = rb_unreachable([n for (m, n) in funcs if m == 'pf'])
    missed = [n for (m, b), f in files.items() if m == 'pf'
              for n in f['miss'] if n not in dead]
    uncalled = no_caller(missed)
    dead |= uncalled
    sh_ = sm_ = 0
    unrun = []
    for (module, base), f in files.items():
        keep = (lambda n: n not in dead) if module == 'pf' else \
            (lambda n: n in scoped)
        sh_ += sum(1 for n in f['hit'] if keep(n))
        miss = [n for n in f['miss'] if keep(n)]
        sm_ += len(miss)
        if module == 'kernel':
            unrun += ['%s:%s' % (base, n) for n in miss]
    lines.append('Scoped (pf.ko and the %d stack functions land/pf changed): '
                 '%d of %d run (%d%%).' % (len(scoped), sh_, sh_ + sm_,
                                          100 * sh_ // max(1, sh_ + sm_)))
    lines.append('Changed stack functions not run: ' + ', '.join(sorted(unrun)))
    lines.append('Excluded from the scope, %d generated tree functions whose '
                 'operation pf never uses: %s' % (len(dead - uncalled),
                 ', '.join(sorted(dead - uncalled))))
    lines.append('Excluded from the scope, %d functions pf\'s source never '
                 'calls or refers to (dead code): %s' % (len(uncalled),
                 ', '.join(sorted(uncalled))))
    lines.append('Total: %d of %d probed functions run (%d%%).' % (
        th, th + tm, 100 * th // max(1, th + tm)))
    text = '\n'.join(lines)
    if md:
        open(md, 'w').write(text + '\n')
    print(text)


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == 'run':
        args = sys.argv[4:]
        skip = set()
        if args[:1] == ['--skip']:
            for p in args[1].split(','):
                skip |= {k for k, v in json.load(open(p))['counts'].items()
                         if v}
            args = args[2:]
        run(sys.argv[2], sys.argv[3], args, skip)
    elif cmd == 'boot':
        boot(sys.argv[2], sys.argv[3])
    elif cmd == 'merge':
        merge(sys.argv[2], sys.argv[3:])
    elif cmd == 'report':
        md = None
        if '--md' in sys.argv:
            md = sys.argv[sys.argv.index('--md') + 1]
        report(sys.argv[2], md)
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    main()
