#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Offline coverage of HyperTrace kernel and guest sources.

Original kernel source files are compiled unmodified as kernel translation
units (-D_KERNEL, the amd64 GENERIC opt_global.h, the tree's own headers),
linked with the audited shim in tests/kcov, run, and measured with LLVM
source-based coverage.  Counters therefore map to the real file paths and
whole-file denominators are reported.  Nothing here loads modules, opens
devices or runs virtual machines.

usage: coverage-kernel.py OUTPUT [--suite NAME ...] [--sanitize] [--list]
OUTPUT must be a new directory under /usr/obj.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import os
import shutil
import subprocess
import sys
import concurrent.futures

ROOT = Path(__file__).resolve().parents[3]
SYS = ROOT / 'sys'
KCOV = Path(__file__).resolve().parent / 'kcov'
NCPU = os.cpu_count() or 1

# Kernel names whose libc namesakes differ in signature or semantics.  Every
# kernel-ABI object gets these renamed so they bind to the shim, never libc.
RENAME = ['malloc', 'free', 'realloc', 'reallocf', 'printf', 'vprintf', 'log',
          'explicit_bzero', 'arc4random', 'arc4random_buf', 'strdup',
          'strndup', 'pause', 'random', 'qsort', 'bsearch', 'getenv',
          'vsnprintf', 'snprintf', 'sprintf', 'vsprintf', 'time', 'sleep',
          'abort', 'exit', 'signal', 'kill', 'index', 'rindex', 'atoi',
          'strtol', 'strtoul', 'strtoq', 'strtouq', 'memcchr', 'clock_gettime',
          'fls', 'flsl', 'ffs', 'ffsl', 'strsep', 'sscanf']
# Kernel names that may bind to libc because the contract is identical for
# the arguments kernel code passes.  Anything else unresolved by the shim
# fails the build instead of silently binding to an unrelated libc symbol.
LIBC_OK = {'memcpy', 'memset', 'memmove', 'memcmp', 'bcmp', 'bcopy', 'bzero',
           'strlen', 'strnlen', 'strcmp', 'strncmp', 'strlcpy', 'strlcat',
           'strchr', 'strrchr', 'strcpy', 'strncpy', 'strstr', 'memchr',
           'strcasecmp', 'strncasecmp', 'strspn', 'strcspn'}
# Shim implementations of renamed symbols live in khx_kern.c and are renamed
# there too, so khx_k_snprintf etc. would need definitions; route the
# formatted-output family to libc explicitly.
LIBC_ALIASES = {'vsnprintf': 'vsnprintf', 'snprintf': 'snprintf',
                'sprintf': 'sprintf', 'vsprintf': 'vsprintf'}

GEN_IFS = ['kern/device_if.m', 'kern/bus_if.m', 'dev/virtio/virtio_if.m',
           'dev/virtio/virtio_bus_if.m', 'kern/linker_if.m']

SUITES = {
    'dttransport': {
        'production': ['sys/dev/dttransport/dttransport.c'],
        'tests': ['t_dttransport.c'],
        'shims': [],
        'component': 'guest transport',
    },
    'virtio_dtrace': {
        'production': ['sys/dev/virtio/dtrace/virtio_dtrace.c'],
        'deps': ['sys/dev/dttransport/dttransport.c', 'sys/kern/subr_mbufid.c',
                 'sys/kern/subr_msgid.c', 'sys/kern/subr_sglist.c'],
        'tests': ['t_virtio_dtrace.c'],
        'shims': ['khx_virtio.c', 'khx_sysctl.c'],
        'component': 'guest driver',
    },
}

_ZINC = 'sys/contrib/openzfs/include'
DTRACE_CFLAGS = [
    '-D_SYS_VMEM_H_', '-D__KERNEL__', '-DSMP',
    '-I' + str(ROOT / _ZINC), '-I' + str(ROOT / _ZINC / 'os/freebsd'),
    '-I' + str(ROOT / _ZINC / 'os/freebsd/spl'),
    '-I' + str(ROOT / _ZINC / 'os/freebsd/zfs'),
    '-I' + str(SYS / 'cddl/compat/opensolaris'),
    '-I' + str(SYS / 'cddl/contrib/opensolaris/uts/common'),
    '-include', str(ROOT / _ZINC / 'os/freebsd/spl/sys/ccompile.h'),
    '-I' + str(SYS / 'cddl/contrib/opensolaris/uts/intel'),
    '-I' + str(SYS / 'cddl/dev/dtrace/x86'),
    '-I' + str(SYS / 'cddl/dev/dtrace'),
    '-I' + str(SYS / 'cddl/dev/dtrace/amd64'),
    '-I' + str(SYS / 'cddl/contrib/opensolaris/uts/common/dtrace'),
    '-I' + str(SYS / 'cddl/contrib/opensolaris/common/util'),
    '-I' + str(SYS / 'cddl/dev/hypertrace'),
    '-DDIS_MEM', '-Wno-parentheses', '-Wno-cast-qual', '-Wno-pointer-sign',
    '-include', str(SYS / 'cddl/compat/opensolaris/sys/debug_compat.h'),
    '-include', str(KCOV / 'khx_cpuid.h'),
]
SUITES['dtrace_vm_subr'] = {
    'production': ['sys/cddl/dev/dtrace/amd64/dtrace_vm_subr.c'],
    'tests': ['t_vm_subr.c'],
    'shims': [],
    'cflags': ['-include', str(KCOV / 'khx_vm_subr_prelude.h')],
    'component': 'amd64 guest page walk',
}
SUITES['dtrace_hypertrace'] = {
    'production': ['sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c',
                   'sys/cddl/dev/hypertrace/hypertrace.c',
                   'sys/cddl/dev/hypertrace/hypertrace_map.c',
                   'sys/cddl/dev/dtrace/amd64/dtrace_isa.c',
                   'sys/cddl/dev/dtrace/dtrace_immstack.c'],
    'report_extra': ['sys/cddl/dev/dtrace/dtrace_ioctl.c',
                     'sys/cddl/dev/dtrace/dtrace_load.c',
                     'sys/cddl/dev/dtrace/dtrace_unload.c',
                     'sys/cddl/dev/dtrace/dtrace_sysctl.c',
                     'sys/cddl/dev/dtrace/dtrace_anon.c',
                     'sys/cddl/dev/dtrace/dtrace_modevent.c',
                     'sys/cddl/dev/dtrace/dtrace_vtime.c',
                     'sys/cddl/dev/dtrace/dtrace_debug.c',
                     'sys/cddl/dev/dtrace/dtrace_db.c'],
    'deps': ['sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace_xoroshiro128_plus.c',
             'sys/cddl/compat/opensolaris/kern/opensolaris.c',
             'sys/libkern/murmur3_32.c'],
    'tests': ['t_dtrace.c'],
    'corpus': 'dtrace-corpus.d',
    'shims': ['khx_virtio.c', 'khx_sysctl.c'],
    'module_shims': ['khx_dtrace.c'],
    'cflags': DTRACE_CFLAGS,
    'component': 'kernel HyperTrace',
    'timeout': 1200,
}


# amd64 VMM HyperTrace hooks (vmm.c, x86.c, vmm_dev_machdep.c; vmm_vm.c as
# the real vCPU state/reinit dependency).  khx_vmm_cpu.h routes the
# privileged CR0/CR4/XCR0 accesses of vm_run() and CPUID to a model.
VMM_CFLAGS = ['-DVMM_KEEP_STATS', '-I' + str(SYS / 'amd64/vmm'),
              '-I' + str(SYS / 'amd64/vmm/io'),
              '-include', str(KCOV / 'khx_vmm_cpu.h')]
SUITES['vmm_hypertrace'] = {
    'production': ['sys/amd64/vmm/vmm.c', 'sys/amd64/vmm/x86.c',
                   'sys/amd64/vmm/vmm_dev_machdep.c', 'sys/dev/vmm/vmm_dev.c'],
    'deps': ['sys/dev/vmm/vmm_vm.c', 'sys/amd64/vmm/x86_cpuid.c'],
    'tests': ['t_vmm_ht.c'],
    'shims': ['khx_sysctl.c'],
    'module_shims': ['khx_vmm.c', 'khx_vmm_stubs.c'],
    'cflags': VMM_CFLAGS,
    'component': 'amd64 VMM HyperTrace hooks',
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(cmd, log, **kw):
    with open(log, 'a') as f:
        f.write('$ ' + ' '.join(map(str, cmd)) + '\n')
        f.flush()
        r = subprocess.run(list(map(str, cmd)), stdout=f, stderr=subprocess.STDOUT,
                           **kw)
    if r.returncode != 0:
        raise SystemExit(f'command failed ({r.returncode}); see {log}')
    return r


def prepare_gen(out):
    gen = out / 'gen'
    gen.mkdir()
    for name, target in (('machine', 'amd64/include'), ('x86', 'x86/include'),
                         ('i386', 'i386/include')):
        (gen / name).symlink_to(SYS / target)
    log = out / 'gen.log'
    for m in GEN_IFS:
        for flag in ('-h', '-c'):
            run(['awk', '-f', SYS / 'tools/makeobjops.awk', SYS / m, flag],
                log, cwd=gen)
    for flag in ('-h', '-p', '-q'):
        run(['awk', '-f', SYS / 'tools/vnode_if.awk', SYS / 'kern/vnode_if.src',
             flag], log, cwd=gen)
    shutil.copy(KCOV / 'opt_global.GENERIC.h', gen / 'opt_global.h')
    for opt in ['opt_kstack_pages.h', 'opt_nfs.h', 'opt_hwpmc_hooks.h',
                'opt_ddb.h', 'opt_kdtrace.h', 'opt_vm.h', 'opt_bhyve_snapshot.h',
                'opt_inet.h', 'opt_inet6.h', 'opt_capsicum.h', 'opt_kld.h',
                'opt_hwpmc_hooks.h', 'opt_stack.h', 'opt_witness.h']:
        (gen / opt).write_text('')
    return gen


def kflags(gen, coverage, sanitize, module_flags=()):
    # Module flags precede the generic kernel include path, as in kmod.mk.
    flags = ['-O0', '-g', '-nostdinc', '-D_KERNEL', '-DKLD_MODULE',
             '-DHAVE_KERNEL_OPTION_HEADERS', '-include', str(gen / 'opt_global.h'),
             *module_flags, '-I' + str(gen), '-I' + str(SYS), '-I' + str(SYS / 'contrib/ck/include'),
             '-I' + str(KCOV), '-fno-common', '-ffreestanding', '-fwrapv',
             '-fno-omit-frame-pointer', '-std=gnu17', '-Wno-unused',
             '-Wno-error', '-ferror-limit=50']
    if coverage:
        flags += ['-fprofile-instr-generate', '-fcoverage-mapping',
                  '-fprofile-update=atomic']
    if sanitize:
        # SYSINIT/kobj dispatch call through deliberately generic function
        # pointer types; that idiom is not what the sanitizer run checks.
        flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                  '-fno-sanitize=function']
    return flags


def build_suite(name, spec, out, gen, coverage, sanitize, log):
    bdir = out / name
    bdir.mkdir()
    objs = []
    jobs = []
    kf = kflags(gen, coverage, sanitize, spec.get('cflags', []))
    base = kflags(gen, coverage, sanitize)
    for src in spec['production'] + spec.get('deps', []):
        jobs.append((ROOT / src, bdir / (Path(src).stem + '.o'), kf + spec.get(
            'prod_cflags', [])))
    # Shims written against the plain kernel headers keep those flags; the
    # suite's own tests and module shims use the module's flags.
    for src in spec['tests'] + spec.get('module_shims', []):
        jobs.append((KCOV / src, bdir / (Path(src).stem + '.o'), kf))
    for src in spec['shims'] + ['khx_kern.c']:
        jobs.append((KCOV / src, bdir / (Path(src).stem + '.o'), base))
    hflags = ['-O0', '-g', '-std=gnu17', '-pthread', '-Wall', '-Werror']
    if sanitize:
        hflags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all']
    host = (KCOV / 'khx_host.c', bdir / 'khx_host.o', hflags)

    def compile_one(job):
        src, obj, flags = job
        clog = bdir / (obj.stem + '.compile.log')
        run(['cc', '-c', *flags, src, '-o', obj], clog)
        return obj

    with concurrent.futures.ThreadPoolExecutor(NCPU) as ex:
        kobjs = list(ex.map(compile_one, jobs))
        hobj = ex.submit(compile_one, host).result()
    # Rename libc-colliding kernel symbols in every kernel-ABI object.
    redef = bdir / 'redefine.txt'
    redef.write_text(''.join(f'{s} khx_k_{s}\n' for s in RENAME
                             if s not in LIBC_ALIASES))
    for obj in kobjs:
        run(['llvm-objcopy', '--redefine-syms', redef, obj], log)
    # Audit unresolved kernel symbols.
    defined, undefined = set(), set()
    for obj in kobjs + [hobj]:
        r = subprocess.run(['llvm-nm', '--defined-only', '-j', str(obj)],
                           capture_output=True, text=True, check=True)
        defined |= set(r.stdout.split())
    for obj in kobjs:
        r = subprocess.run(['llvm-nm', '--undefined-only', '-j', str(obj)],
                           capture_output=True, text=True, check=True)
        undefined |= set(r.stdout.split())
    unresolved = sorted(s for s in undefined - defined
                        if not s.startswith(('__start_set_', '__stop_set_',
                                             '__llvm_', '__asan', '__ubsan',
                                             '__sanitizer', '__profc', '__profd',
                                             '__start_asan', '__stop_asan'))
                        and s not in LIBC_OK and s not in LIBC_ALIASES)
    (bdir / 'unresolved.txt').write_text('\n'.join(unresolved) + '\n')
    if unresolved:
        raise SystemExit(f'{name}: unresolved kernel symbols: '
                         + ' '.join(unresolved))
    exe = bdir / (name + '-test')
    link = ['cc', '-pthread', '-o', exe, *kobjs, hobj]
    if coverage:
        link.insert(1, '-fprofile-instr-generate')
    if sanitize:
        link.insert(1, '-fsanitize=address,undefined')
    run(link, log)
    return exe


DEFAULT_LIBDTRACE_OBJ = Path('/usr/obj/5BSD-hypertrace-validation/'
                             'coverage-compiler-20261020/usr/obj/5BSD-hypertrace/'
                             'amd64.amd64')


def build_dof_corpus(out, corpus, obj, log):
    """Compile the D corpus to DOF with the worktree libdtrace (userland,
    NODEV|NOSYS).  Returns the DOF directory and provenance."""
    gdir = out / 'dofgen'
    gdir.mkdir(exist_ok=True)
    inc = gdir / 'include' / 'sys'
    inc.mkdir(parents=True, exist_ok=True)
    if not (inc / 'hypertrace.h').exists():
        (inc / 'hypertrace.h').symlink_to(SYS / 'sys/hypertrace.h')
    lib = obj / 'cddl/lib/libdtrace'
    common = ROOT / 'cddl/contrib/opensolaris/lib/libdtrace/common'
    prefix = Path(*obj.parts[:obj.parts.index('usr', 3)])
    exe = gdir / 'dofgen'
    if not exe.exists():
        run(['cc', '-g', '-O0', '-I' + str(gdir / 'include'), '-I' + str(common),
             '-I' + str(ROOT / 'sys/cddl/compat/opensolaris'),
             '-I' + str(ROOT / 'cddl/compat/opensolaris/include'),
             '-I' + str(ROOT / 'cddl/contrib/opensolaris/head'),
             '-I' + str(ROOT / 'sys/cddl/contrib/opensolaris/uts/common'),
             '-I' + str(ROOT / 'cddl/contrib/opensolaris/lib/libctf/common'),
             '-I' + str(prefix / 'source-includes'),
             KCOV / 'dofgen.c', '-L' + str(lib), '-Wl,-rpath,' + str(lib),
             '-ldtrace', '-lelf', '-lxo', '-o', exe], log)
    ddir = gdir / ('dof-' + Path(corpus).stem)
    ddir.mkdir(exist_ok=True)
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in (
        'cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
    env['LLVM_PROFILE_FILE'] = str(gdir / 'dofgen-%p.profraw')
    with open(log, 'a') as f:
        r = subprocess.run([str(exe), str(KCOV / corpus), str(ddir)], env=env,
                           stdout=f, stderr=subprocess.STDOUT)
    if r.returncode != 0:
        raise SystemExit(f'D corpus compilation failed; see {log}')
    tools = build_tool_dofs(gdir, ddir, obj, prefix, env, log)
    return ddir, {'libdtrace': str(lib / 'libdtrace.so.2'),
                  'libdtrace_sha256': sha(lib / 'libdtrace.so.2'),
                  'corpus_sha256': sha(KCOV / corpus),
                  'tool_dofs': tools}


# Consumers that exec without linking (the typing agent's tool-dof step):
# each run's exact ENABLE DOF is saved as tool_<n>.dof for the kernel tests.
TOOL_RUNS = [('lockstat', a) for a in ([], ['-H'], ['-A', '-s', '8'],
                                       ['-C', '-t'], ['-h', '-s', '4'], ['-I'],
                                       ['-E'], ['-T'])] + \
    [('plockstat', a) for a in ([], ['-H'], ['-C'], ['-s', '8'])]


def build_tool_dofs(gdir, ddir, obj, prefix, env, log):
    osrc = ROOT / 'cddl/contrib/opensolaris'
    zfs = ROOT / 'sys/contrib/openzfs'
    common = osrc / 'lib/libdtrace/common'
    tinc = ['-DIN_BASE', '-DSKIP_SPL_SYS_CONDVAR_H', '-DHAVE_ISSETUGID',
            '-DNEED_ERRLOC', '-I' + str(prefix / 'source-includes'),
            '-I' + str(zfs / 'include'), '-I' + str(zfs / 'lib/libspl/include'),
            '-I' + str(zfs / 'lib/libspl/include/os/freebsd'),
            '-I' + str(ROOT / 'sys'),
            '-I' + str(ROOT / 'cddl/compat/opensolaris/include'),
            '-I' + str(ROOT / 'sys/cddl/compat/opensolaris'),
            '-I' + str(osrc / 'head'), '-I' + str(common),
            '-I' + str(osrc / 'lib/libctf/common'),
            '-I' + str(osrc / 'lib/libproc/common'),
            '-I' + str(ROOT / 'sys/cddl/contrib/opensolaris/uts/common'),
            '-I' + str(ROOT / 'sys/cddl/contrib/opensolaris/compat'),
            '-I' + str(ROOT / 'cddl/lib/libdtrace'),
            '-I' + str(ROOT / 'lib/libproc'), '-I' + str(KCOV.parent)]
    tlibs = ['-L' + str(obj / 'cddl/lib/libdtrace'),
             '-L' + str(obj / 'cddl/lib/libctf'), '-L' + str(obj / 'lib/libproc'),
             '-L' + str(obj / 'lib/librtld_db'),
             '-Wl,-rpath,' + str(obj / 'cddl/lib/libdtrace'),
             '-ldtrace', '-lctf', '-lproc', '-lelf', '-lrt', '-lpthread']
    wraps = ['-Wl,--wrap=' + f for f in ('symtab_init', 'dtrace_open',
                                          'dtrace_program_strcompile',
                                          'dtrace_proc_create')]
    srcs = {'lockstat': [osrc / 'cmd/lockstat/lockstat.c',
                         osrc / 'cmd/lockstat/sym.c'],
            'plockstat': [osrc / 'cmd/plockstat/plockstat.c']}
    cap = gdir / 'tool-dof-capture.o'
    if not cap.exists():
        run(['cc', '-g', '-w', *tinc, '-c', KCOV / 'tool-dof-capture.c',
             '-o', cap], log)
    for tool, files in srcs.items():
        if not (gdir / tool).exists():
            run(['cc', '-g', '-w', *tinc, *files, cap, *wraps, *tlibs,
                 '-o', gdir / tool], log)
    made = []
    for n, (tool, args) in enumerate(TOOL_RUNS):
        dof = ddir / f'tool_{n}.dof'
        tenv = env | {'TOOLDOF_OUT': str(dof)}
        r = subprocess.run([str(gdir / tool), *args, 'true'], env=tenv,
                           cwd=gdir, capture_output=True, text=True, timeout=600)
        with open(log, 'a') as f:
            f.write(f'$ {tool} {" ".join(args)} true\n{r.stdout}{r.stderr}')
        if not dof.exists() or 'typecast=0' not in r.stdout:
            raise SystemExit(f'tool DOF capture failed: {tool} {args}; see {log}')
        made.append(' '.join([tool, *args]))
    return made


def changed_lines(rel):
    """Lines of the working-tree file that differ from HEAD (added/changed)."""
    r = subprocess.run(['git', '-C', str(ROOT), 'diff', '-U0', 'HEAD', '--', rel],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    if not r.stdout:
        st = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '--error-unmatch',
                             rel], capture_output=True)
        return None if st.returncode != 0 else set()
    lines = set()
    for line in r.stdout.splitlines():
        if line.startswith('@@'):
            plus = line.split('+')[1].split(' ')[0]
            start, _, count = plus.partition(',')
            count = int(count) if count else 1
            lines.update(range(int(start), int(start) + count))
    return lines


def summarize(export, prod_paths):
    data = json.loads(export.read_text())['data'][0]
    files = {}
    for f in data['files']:
        if f['filename'] in prod_paths:
            files[f['filename']] = f
    funcs = {}
    for fn in data['functions']:
        fname = fn['filenames'][0] if fn['filenames'] else None
        if fname in prod_paths:
            funcs.setdefault(fname, []).append(fn)
    result = {}
    for path in prod_paths:
        f = files.get(path)
        if f is None:
            result[path] = {'mapped': False}
            continue
        s = f['summary']
        flist = []
        for fn in funcs.get(path, []):
            r0 = fn['regions'][0]
            # Function entry region: [line_start, col_start, line_end, col_end, count, ...]
            start = min(r[0] for r in fn['regions'] if r[5] == 0 and r[7] == 0) \
                if fn['regions'] else 0
            end = max(r[2] for r in fn['regions'] if r[5] == 0 and r[7] == 0) \
                if fn['regions'] else 0
            br = fn.get('branches', [])
            outcomes = 2 * len(br)
            covered = sum((b[4] > 0) + (b[5] > 0) for b in br)
            flist.append({'name': fn['name'], 'count': fn['count'],
                          'start': start, 'end': end,
                          'branches_total': outcomes, 'branches_covered': covered})
        result[path] = {'mapped': True, 'lines': s['lines'],
                        'branches': s['branches'], 'functions': s['functions'],
                        'function_list': sorted(flist, key=lambda x: x['start'])}
    return result


MACRO_CLASSES = [
    ('assertion', ('KASSERT', 'MPASS', 'VERIFY', 'ASSERT', 'CTASSERT')),
    ('queue-macro', ('TAILQ_', 'STAILQ_', 'LIST_', 'SLIST_')),
    ('malloc-macro', ('malloc(',)),
]


def classify_branches(lcov_text, export, path):
    """Split LLVM's branch outcomes into those decided by conditions written
    in the measured file and those inside macro expansions, by line.

    LLVM's lcov export reports exactly the counted outcomes (folded constant
    outcomes omitted) with macro-expansion outcomes attributed to the
    invocation line.  The JSON export lists the measured file's own branch
    regions.  Per line, macro outcomes = lcov outcomes - own outcomes."""
    lcov = {}
    for line in lcov_text.splitlines():
        if line.startswith('BRDA:'):
            ln, _blk, _br, taken = line[5:].split(',')
            lcov.setdefault(int(ln), []).append(0 if taken == '-' else int(taken))
    data = json.loads(export.read_text())['data'][0]
    text = Path(path).read_text().splitlines()
    # Lines belonging to macro definitions in this file: their branches are
    # reported by lcov at each invocation line, like header macros.
    define_lines, local_macros, cont = set(), [], False
    for i, t in enumerate(text, 1):
        s = t.lstrip()
        if cont or s.startswith('#define') or s.startswith('# define'):
            define_lines.add(i)
            if s.startswith('#define'):
                name = s.split()[1].split('(')[0]
                local_macros.append(name)
        cont = t.rstrip().endswith('\\')
    own = {}
    # A .c file #included by two translation units (dtrace_db.c) has each
    # source branch region once per unit: merge regions by source span.
    regions = {}
    for f in data['files']:
        if f['filename'] == path:
            for b in f['branches']:
                if b[0] not in define_lines:
                    key = (b[0], b[1], b[2], b[3])
                    t, e = regions.get(key, (0, 0))
                    regions[key] = (t + b[4], e + b[5])
    for key in sorted(regions):
        own.setdefault(key[0], []).extend(regions[key])
    src = {'count': 0, 'covered': 0}
    macro = {}
    uncovered = []
    for ln in sorted(lcov):
        outs = lcov[ln]
        mine = own.get(ln, [])
        if len(mine) > len(outs):
            raise SystemExit(f'{path}:{ln}: own branches exceed counted outcomes')
        src['count'] += len(mine)
        src['covered'] += sum(1 for v in mine if v > 0)
        own_zero = sum(1 for v in mine if v == 0)
        macro_n = len(outs) - len(mine)
        macro_zero = sum(1 for v in outs if v == 0) - own_zero
        line_text = text[ln - 1].strip()
        cls = 'macro-other'
        if any(m + '(' in line_text for m in local_macros):
            cls = 'file-macro'
        for name, keys in MACRO_CLASSES:
            if any(k in line_text for k in keys):
                cls = name
                break
        if macro_n:
            m = macro.setdefault(cls, {'count': 0, 'covered': 0})
            m['count'] += macro_n
            m['covered'] += macro_n - macro_zero
        if own_zero:
            uncovered.append({'line': ln, 'kind': 'source', 'outcomes': own_zero,
                              'text': line_text})
        if macro_zero:
            uncovered.append({'line': ln, 'kind': cls, 'outcomes': macro_zero,
                              'text': line_text})
    total = sum(len(v) for v in lcov.values())
    covered = sum(1 for v in lcov.values() for x in v if x > 0)
    return {'raw': {'count': total, 'covered': covered},
            'source_text': src, 'macro': macro, 'uncovered': uncovered}


WAIVERS = KCOV / 'waivers.txt'
BRANCH_WAIVERS = KCOV / 'branch-waivers.txt'
# Macro-expansion branch outcomes are classified from the expansion's own
# branch regions on that line (llvm-cov JSON).  An uncovered region is
#  constant: a condition the compiler sees as a constant ("0"/"1" of
#            do { } while (0), __builtin_constant_p(), _Generic, sizeof()
#            comparisons, malloc(9)'s tests of constant flags);
#  assert:   an assertion's failure test (ASSERT's EX / dtrace_assfail, and
#            the __predict_false() panic guards of KASSERT, MPASS and the
#            QUEUE_MACRO_DEBUG checks inside queue(3) macros) -- only when
#            every macro expanded at top level on the line is an assertion
#            or queue macro.
# A line's uncovered macro outcomes are waived only when every uncovered
# region on it is constant or assert; anything else stays open.
ASSERT_MACROS = {'ASSERT', 'ASSERT3U', 'ASSERT3S', 'ASSERT3P', 'KASSERT',
                 'VERIFY', 'VERIFY3U', 'MPASS', 'VTDTR_STATE_ASSERT',
                 'mtx_assert', 'sx_assert'}
QUEUE_MACRO_RE = re.compile(r'^(S?TAILQ|S?LIST)_[A-Z_]+$')


def macro_region_kind(fname, text, top_macros, counts):
    base = Path(fname).name
    t = text.strip()
    if t in ('0', '1') or t.startswith('__builtin_constant_p') or \
            t.startswith('_Generic') or 'sizeof(' in t or \
            (base == 'malloc.h' and 'flags' in t):
        return 'macro-constant'
    # malloc(9) with constant M_WAITOK never evaluates its NULL test.
    if 'malloc' in top_macros and base == 'cdefs.h' and \
            t == '__builtin_expect((exp), 1)' and counts == [0, 0]:
        return 'macro-constant'
    # mutex_init()'s checks of its constant name literal.
    if top_macros == {'mutex_init'} and '_name' in t:
        return 'macro-constant'
    allassert = top_macros and all(m in ASSERT_MACROS or QUEUE_MACRO_RE.match(m)
                                   for m in top_macros)
    if base == 'dtrace_impl.h' and (t in ('EX', '(EX)') or 'assfail' in t):
        return 'assert'
    if allassert and (t in ('__builtin_expect((exp), 0)',
                            '__builtin_expect(!!(x), 0)', 'exp')):
        return 'assert'
    return None


def load_waivers():
    """Waivers for changed lines that are infeasible by construction.

    Format, one per line (# comments):  FILE|FUNCTION|CLASS|GUARD-REGEX|REASON
    (the regex may contain '|'; the reason may not)
    A waiver covers each maximal run of uncovered changed lines inside
    FUNCTION whose guard (the six source lines before the run, plus the run's
    first line) matches GUARD-REGEX.  Waived lines stay in the denominator of
    the plain view; the waived view removes them, and every waiver that
    matches nothing is reported as stale."""
    out = []
    if not WAIVERS.exists():
        return out
    for n, line in enumerate(WAIVERS.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        f, fn, cls, rest = (x.strip() for x in line.split('|', 3))
        rx, why = (x.strip() for x in rest.rsplit('|', 1))
        out.append({'file': f, 'function': fn, 'class': cls,
                    're': re.compile(rx), 'regex': rx, 'reason': why,
                    'line': n})
    return out


def apply_waivers(path, uncovered, function_list, waivers):
    rel = str(Path(path).relative_to(ROOT))
    mine = [w for w in waivers if w['file'] == rel]
    apply_waivers.line_class = {}
    if not mine:
        return [], {}, []
    text = Path(path).read_text().splitlines()
    spans = sorted((f['start'], f['end'], f['name'].split(':')[-1])
                   for f in function_list)

    def func_of(ln):
        best = None
        for a, b, n in spans:
            if a <= ln <= b:
                best = n
        return best

    runs, cur = [], []
    for ln in uncovered:
        if cur and (ln - cur[-1] > 3 or func_of(ln) != func_of(cur[0])):
            runs.append(cur)
            cur = []
        cur.append(ln)
    if cur:
        runs.append(cur)
    waived, classes, used = [], {}, set()
    line_class = {}
    for run in runs:
        fn = func_of(run[0])
        guard = '\n'.join(text[max(0, run[0] - 7):run[0]])
        for w in mine:
            if w['function'] == fn and w['re'].search(guard):
                waived.extend(run)
                classes[w['class']] = classes.get(w['class'], 0) + len(run)
                used.add(w['line'])
                for ln in run:
                    line_class[ln] = w['class']
                break
    stale = [f"{w['file']}:{w['function']}:{w['regex']}" for w in mine
             if w['line'] not in used]
    apply_waivers.line_class = line_class
    return waived, classes, stale


def load_branch_waivers():
    """Branch-outcome waivers, one per line (# comments):
    FILE|FUNCTION|CLASS|LINE-REGEX|CONDITION|OUTCOME|REASON
    LINE-REGEX must match the whole (stripped) source line of the branch.  CONDITION
    is a regex that must match the whole condition text, or MACRO for the
    line's macro-expansion outcomes.  OUTCOME is T, F or * (either).  An
    entry that waives nothing is reported as stale."""
    out = []
    if not BRANCH_WAIVERS.exists():
        return out
    for n, line in enumerate(BRANCH_WAIVERS.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = [x.strip() for x in line.split('|')]
        if len(parts) != 7:
            raise SystemExit(f'{BRANCH_WAIVERS}:{n}: expected 7 fields')
        f, fn, cls, lrx, cond, outc, why = parts
        if outc not in ('T', 'F', '*'):
            raise SystemExit(f'{BRANCH_WAIVERS}:{n}: outcome must be T, F or *')
        out.append({'file': f, 'function': fn, 'class': cls,
                    'lre': re.compile(lrx), 'cond': cond,
                    'cre': None if cond == 'MACRO' else re.compile(cond),
                    'outcome': outc, 'reason': why, 'line': n,
                    'regex': lrx})
    return out


def branch_view(lcov_lines, path, export, function_list, changed, line_class,
                bwaivers):
    """Changed-line branch outcomes (the lcov outcomes the plain view counts)
    split into: outcomes of conditions written in the file (JSON branch
    regions, merged by span), and macro-expansion outcomes (the remainder per
    line).  Uncovered outcomes are waived by: the line's own line waiver
    (same class); assertion/constant macros (classes 'assert',
    'macro-constant'); or an explicit branch waiver."""
    lc = {}
    for line in lcov_lines:
        if line.startswith('BRDA:'):
            ln, _b, _r, taken = line[5:].split(',')
            lc.setdefault(int(ln), []).append(0 if taken == '-' else int(taken))
    data = json.loads(export.read_text())['data'][0]
    text = Path(path).read_text().splitlines()
    own, macros, mregs = {}, {}, {}
    mtext = {}

    def region_text(fname, b):
        if fname not in mtext:
            mtext[fname] = Path(fname).read_text().splitlines()
        t = mtext[fname][b[0] - 1]
        return t[b[1] - 1:(b[3] - 1 if b[2] == b[0] else None)]

    for f in data['files']:
        if f['filename'] != path:
            continue
        for b in f['branches']:
            k = tuple(b[:4])
            a = own.setdefault(b[0], {}).setdefault(k, [0, 0])
            a[0] += b[4]
            a[1] += b[5]
        for e in f['expansions']:
            sr = e['source_region']
            if sr[5] != 0:
                continue
            t = text[sr[0] - 1][sr[1] - 1:(sr[3] - 1 if sr[2] == sr[0] else None)]
            macros.setdefault(sr[0], set()).add(t.strip())
            for b in e['branches']:
                fn_ = e['filenames'][b[6]]
                k = (fn_, b[0], b[1], b[2], b[3])
                a = mregs.setdefault(sr[0], {}).setdefault(k, [0, 0])
                a[0] += b[4]
                a[1] += b[5]
    spans = sorted((f['start'], f['end'], f['name'].split(':')[-1])
                   for f in function_list)

    def func_of(ln):
        best = None
        for a, b, n in spans:
            if a <= ln <= b:
                best = n
        return best

    rel = str(Path(path).relative_to(ROOT))
    mine = [w for w in bwaivers if w['file'] == rel]
    used = set()
    define_lines, cont = set(), False
    for i, t in enumerate(text, 1):
        st = t.lstrip()
        if cont or st.startswith('#define') or st.startswith('# define'):
            define_lines.add(i)
        cont = t.rstrip().endswith('\\')
    total = covered = 0
    classes = {}
    open_items = []

    def waive(cls, n=1):
        classes[cls] = classes.get(cls, 0) + n

    def explicit(ln, cond_text, outcome):
        fn = func_of(ln)
        for w in mine:
            # FUNCTION "None": a line outside any function (a macro body).
            if w['function'] != str(fn) or \
                    not w['lre'].fullmatch(text[ln - 1].strip()):
                continue
            if w['outcome'] not in ('*', outcome):
                continue
            if cond_text is None:
                if w['cond'] != 'MACRO':
                    continue
            elif w['cre'] is None or not w['cre'].fullmatch(cond_text):
                continue
            used.add(w['line'])
            return w['class']
        return None

    for ln in sorted(lc):
        if changed is not None and ln not in changed:
            continue
        outs = lc[ln]
        total += len(outs)
        covered += sum(1 for x in outs if x)
        regs = own.get(ln, {})
        own_unc = []
        if ln in define_lines:
            # A condition inside a macro defined in this file (counted at
            # the definition): classify it as a macro region.
            for k, v in sorted(regs.items()):
                ct = text[ln - 1][k[1] - 1:(k[3] - 1 if k[2] == ln else None)]
                for i in (0, 1):
                    if v[i] == 0:
                        kd = macro_region_kind(path, ct, set(), v) or \
                            explicit(ln, ct.strip(), 'TF'[i])
                        if kd:
                            waive(kd)
                        else:
                            open_items.append((ln, func_of(ln), 'cond',
                                               ct.strip(), 'TF'[i]))
            continue
        for k, v in sorted(regs.items()):
            ct = text[ln - 1][k[1] - 1:(k[3] - 1 if k[2] == ln else None)].strip()
            if v[0] == 0:
                own_unc.append((ct, 'T'))
            if v[1] == 0:
                own_unc.append((ct, 'F'))
        mac_unc = sum(1 for x in outs if x == 0) - len(own_unc)
        if ln in line_class:
            waive(line_class[ln], len(own_unc) + max(mac_unc, 0))
            continue
        for ct, oc in own_unc:
            cls = explicit(ln, ct, oc)
            if cls:
                waive(cls)
            else:
                open_items.append((ln, func_of(ln), 'cond', ct, oc))
        if mac_unc > 0:
            ms = macros.get(ln, set())
            kinds, other = set(), []
            for k, v in mregs.get(ln, {}).items():
                if v[0] and v[1]:
                    continue
                kd = macro_region_kind(k[0], region_text(k[0], k[1:]), ms, v)
                if kd is None:
                    other.append(region_text(k[0], k[1:]).strip())
                else:
                    kinds.add(kd)
            if kinds and not other:
                waive('assert' if 'assert' in kinds else 'macro-constant',
                      mac_unc)
            else:
                cls = explicit(ln, None, '*')
                if cls:
                    waive(cls, mac_unc)
                else:
                    open_items.append((ln, func_of(ln), 'macro',
                                       ','.join(sorted(ms)) + ' {' +
                                       '; '.join(sorted(set(other))) + '}',
                                       str(mac_unc)))
    nw = sum(classes.values())
    stale = [f"{w['file']}:{w['function']}:{w['regex']}:{w['cond']}"
             for w in mine if w['line'] not in used]
    return {'count': total, 'covered': covered, 'waived': nw,
            'classes': classes, 'covered_of_unwaived': [covered, total - nw],
            'open': open_items, 'stale_waivers': stale}


def patch_view(lcov_lines, path, function_list, waivers=(), export=None,
               bwaivers=()):
    """Coverage restricted to lines that differ from HEAD (5BSD/HyperTrace
    additions).  Untracked files count every line."""
    rel = str(Path(path).relative_to(ROOT))
    changed = changed_lines(rel)
    da, brda = {}, {}
    for line in lcov_lines:
        if line.startswith('DA:'):
            ln, cnt = line[3:].split(',')[:2]
            da[int(ln)] = int(cnt)
        elif line.startswith('BRDA:'):
            ln, _b, _r, taken = line[5:].split(',')
            brda.setdefault(int(ln), []).append(0 if taken == '-' else int(taken))
    sel = (lambda ln: True) if changed is None else (lambda ln: ln in changed)
    lines = [c for ln, c in da.items() if sel(ln)]
    outs = [x for ln, v in brda.items() if sel(ln) for x in v]
    funcs = [f for f in function_list
             if changed is None or any(f['start'] <= ln <= f['end']
                                       for ln in changed)]
    uncovered_lines = sorted(ln for ln, c in da.items() if sel(ln) and c == 0)
    waived, wclasses, stale = apply_waivers(path, uncovered_lines,
                                            function_list, waivers)
    bview = None
    if export is not None:
        bview = branch_view(lcov_lines, path, export, function_list, changed,
                            apply_waivers.line_class, bwaivers)
    nlines = len(lines)
    ncov = sum(1 for c in lines if c)
    return {
            'waived': {'lines': len(waived), 'classes': wclasses,
                       'stale_waivers': stale,
                       'covered_of_unwaived': [ncov, nlines - len(waived)],
                       'waived_lines': sorted(waived)},'scope': 'untracked file (all lines)' if changed is None else
            'lines changed versus HEAD',
            'lines': {'count': len(lines), 'covered': sum(1 for c in lines if c)},
            'branches': {'count': len(outs), 'covered': sum(1 for x in outs if x)},
            'functions': {'count': len(funcs),
                          'covered': sum(1 for f in funcs if f['count'] > 0),
                          'uncalled': [f['name'] for f in funcs if f['count'] == 0]},
            'uncovered_lines': uncovered_lines,
            'branch_waived': bview}


def line_detail(export, path):
    data = json.loads(export.read_text())['data'][0]
    for f in data['files']:
        if f['filename'] == path:
            return f
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('output')
    ap.add_argument('--suite', action='append')
    ap.add_argument('--sanitize', action='store_true')
    ap.add_argument('--no-coverage', action='store_true')
    ap.add_argument('--libdtrace-obj', default=str(DEFAULT_LIBDTRACE_OBJ))
    args = ap.parse_args()
    out = Path(args.output).resolve()
    if not out.is_relative_to('/usr/obj') or out.exists():
        raise SystemExit('Use a new directory under /usr/obj')
    out.mkdir(parents=True)
    suites = args.suite or list(SUITES)
    coverage = not args.no_coverage
    prod_rel = sorted({p for s in suites for p in SUITES[s]['production']
                       + SUITES[s].get('deps', []) +
                       SUITES[s].get('report_extra', [])})
    harness = sorted(str(p.relative_to(ROOT)) for p in KCOV.iterdir()
                     if p.suffix in ('.c', '.h'))
    before = {p: sha(ROOT / p) for p in prod_rel + harness}
    (out / 'source-before.json').write_text(json.dumps(before, indent=2) + '\n')
    gen = prepare_gen(out)
    log = out / 'build.log'
    results = {}
    for name in suites:
        spec = SUITES[name]
        exe = build_suite(name, spec, out, gen, coverage, args.sanitize, log)
        profiles = out / (name + '-profiles')
        profiles.mkdir()
        env = os.environ.copy()
        env['LLVM_PROFILE_FILE'] = str(profiles / '%p.profraw')
        env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1'
        if 'corpus' in spec:
            ddir, prov = build_dof_corpus(out, spec['corpus'],
                                          Path(args.libdtrace_obj),
                                          out / (name + '-dofgen.log'))
            env['KHX_DOF_DIR'] = str(ddir)
        runlog = out / (name + '-run.log')
        with runlog.open('w') as f:
            r = subprocess.run([str(exe)], stdout=f, stderr=subprocess.STDOUT,
                               env=env, timeout=spec.get('timeout', 600))
        status = r.returncode
        entry = {'binary': str(exe), 'binary_sha256': sha(exe), 'exit': status,
                 'log': str(runlog)}
        if 'corpus' in spec:
            entry['dof_corpus'] = prov
        print(name, 'exit', status, runlog.read_text(errors='replace').strip().splitlines()[-1:],
              flush=True)
        if coverage and status == 0:
            raw = sorted(profiles.glob('*.profraw'))
            listing = out / (name + '-profiles.txt')
            listing.write_text(''.join(f'{p}\n' for p in raw))
            merged = out / (name + '.profdata')
            mlog = out / (name + '-merge.log')
            with mlog.open('w') as f:
                subprocess.run(['llvm-profdata', 'merge', '-sparse', '-f',
                                str(listing), '-o', str(merged)], stdout=f,
                               stderr=subprocess.STDOUT, check=True)
            export = out / (name + '-coverage.json')
            elog = out / (name + '-export.log')
            with export.open('w') as f, elog.open('w') as e:
                subprocess.run(['llvm-cov', 'export', str(exe),
                                '-instr-profile=' + str(merged)], stdout=f,
                               stderr=e, check=True)
            text = out / (name + '-coverage.txt')
            with text.open('w') as f:
                subprocess.run(['llvm-cov', 'show', str(exe),
                                '-instr-profile=' + str(merged),
                                '-show-branches=count', '-show-line-counts-or-regions',
                                *[str(ROOT / p) for p in spec['production'] +
                                  spec.get('report_extra', [])]],
                               stdout=f, stderr=subprocess.DEVNULL, check=True)
            lcov = out / (name + '.lcov')
            with lcov.open('w') as f:
                subprocess.run(['llvm-cov', 'export', '-format=lcov', str(exe),
                                '-instr-profile=' + str(merged)], stdout=f,
                               stderr=subprocess.DEVNULL, check=True)
            lcov_by_file = {}
            cur = None
            for line in lcov.read_text().splitlines():
                if line.startswith('SF:'):
                    cur = line[3:]
                    lcov_by_file[cur] = []
                elif cur is not None:
                    lcov_by_file[cur].append(line)
            entry['merge_log_empty'] = mlog.stat().st_size == 0
            entry['export_log_empty'] = elog.stat().st_size == 0
            entry['files'] = summarize(export, {str(ROOT / p) for p in
                                               spec['production'] +
                                               spec.get('report_extra', [])})
            for path, info in entry['files'].items():
                if info.get('mapped'):
                    cls = classify_branches('\n'.join(lcov_by_file.get(path, [])),
                                            export, path)
                    info['branch_classes'] = cls
                    # LLVM's file summary and its per-line BRDA records can
                    # disagree on covered macro outcomes; both are recorded and
                    # the lower (per-line) value is the one reported.
                    cls['brda'] = dict(cls['raw'])
                    cls['raw'] = {'count': info['branches']['count'],
                                  'covered': min(info['branches']['covered'],
                                                 cls['brda']['covered'])}
                    cls['llvm_summary_covered'] = info['branches']['covered']
                    info['patch'] = patch_view(lcov_by_file.get(path, []), path,
                                               info['function_list'],
                                               load_waivers(), export,
                                               load_branch_waivers())
                    l, b, fn = info['lines'], info['branches'], info['functions']
                    st = cls['source_text']
                    pct = lambda c, n: 100.0 * c / n if n else 100.0
                    rc = cls['raw']['covered']
                    print(f"  {Path(path).relative_to(ROOT)}: lines {l['covered']}/{l['count']}"
                          f" {l['percent']:.2f}%  branches(all) {rc}/{b['count']}"
                          f" {pct(rc, b['count']):.2f}% [llvm summary {b['covered']}]"
                          f"  branches(source) {st['covered']}/{st['count']}"
                          f" {pct(st['covered'], st['count']):.2f}%"
                          f"  functions {fn['covered']}/{fn['count']}", flush=True)
                    for k, v in sorted(cls['macro'].items()):
                        print(f"      macro {k}: {v['covered']}/{v['count']}", flush=True)
                    pv = info['patch']
                    if pv['scope'] != 'untracked file (all lines)':
                        print(f"      changed-vs-HEAD: lines {pv['lines']['covered']}/"
                              f"{pv['lines']['count']} branches {pv['branches']['covered']}/"
                              f"{pv['branches']['count']} functions "
                              f"{pv['functions']['covered']}/{pv['functions']['count']}",
                              flush=True)
                    wv = pv.get('waived', {})
                    if wv.get('lines'):
                        c, n = wv['covered_of_unwaived']
                        print(f"      changed-vs-HEAD excluding {wv['lines']} waived"
                              f" lines: {c}/{n} {100.0 * c / n:.2f}%"
                              f"  {wv['classes']}", flush=True)
                    if wv.get('stale_waivers'):
                        print(f"      STALE waivers: {wv['stale_waivers']}", flush=True)
                    bw = pv.get('branch_waived')
                    if bw and bw['waived']:
                        c, n = bw['covered_of_unwaived']
                        print(f"      changed-vs-HEAD branches excluding {bw['waived']}"
                              f" waived outcomes: {c}/{n} {100.0 * c / n:.2f}%"
                              f"  {bw['classes']}  open {len(bw['open'])}",
                              flush=True)
                    if bw and bw['stale_waivers']:
                        print(f"      STALE branch waivers: {bw['stale_waivers']}",
                              flush=True)
        results[name] = entry
    after = {p: sha(ROOT / p) for p in prod_rel + harness}
    (out / 'source-after.json').write_text(json.dumps(after, indent=2) + '\n')
    summary = {'suites': results, 'sources_unchanged': before == after,
               'production_sha256': {p: before[p] for p in prod_rel},
               'harness_sha256': {p: before[p] for p in harness},
               'compiler': subprocess.run(['cc', '--version'], capture_output=True,
                                          text=True).stdout.splitlines()[0],
               'configuration': 'amd64 GENERIC opt_global.h, -D_KERNEL -DKLD_MODULE, -O0',
               'live_testing': False}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    failed = [n for n, e in results.items() if e['exit'] != 0]
    if failed or before != after:
        raise SystemExit(f'failed suites: {failed}; sources unchanged: {before == after}')


if __name__ == '__main__':
    main()
