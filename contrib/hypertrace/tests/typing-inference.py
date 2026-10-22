#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""HyperTrace type inference, linker relocation and type-file coverage.

Builds the C++ harnesses typing-inference.cc (compiled D corpus checked by
the independent oracle in typing-oracle.h), typing-units.cc (typing rules
and diagnostics on constructed data-flow graphs) and typing-reject.cc
(hand-assembled and mutated DIFOs through hypertrace_link()) against the
instrumented libdtrace of an object tree, and runs every case in its own
child process.

It also builds lockstat and plockstat from their sources with
tool-dof-shim.c and runs them to the DOF dtrace_program_exec() hands the
kernel (they never call hypertrace_link()): no DIF there may hold
TYPECAST, USETX, ULOAD or UULOAD, which the kernel's DIF validator refuses.

The module inventory is supplied by a kldnext()/kldstat() interposer: the
host's /boot/kernel/kernel CTF (hash recorded) plus three CTF fixture
objects compiled here from the C sources below with cc -g and ctfconvert.
No tracing device, module load, daemon or VM is used.

usage: typing-inference.py /usr/obj/new-output-dir /usr/obj/.../amd64.amd64
"""
from pathlib import Path
import hashlib
import re
import json
import os
import subprocess
import sys

FIXTURES = {
    # Types with known layouts for member, subtype and relocation checks.
    'typingfix': r'''
struct tf_small { int a; };
struct tf_big { int a; long b; char c; };
struct tf_pair { int a; long b; };
union tf_u { int i; long l; };
enum tf_e { TF_A, TF_B };
struct tf_bits { unsigned int x:3; unsigned int y:5; };
struct tf_huge { char pad[70000]; int far; };
struct tf_flt { float f; double d; };
struct tf_arr { int arr[4]; char name[8]; };
struct tf_fwd;
struct tf_fwdholder { struct tf_fwd *p; };
struct tf_undef;
struct tf_undefholder { struct tf_undef *p; };
struct thread { int td_tid; long td_x; };
typedef struct tf_pair tf_pair_t;
struct tf_nested { struct tf_pair inner; struct tf_small *sp; };
struct tf_sub8 { char c; short s; int i; long l; unsigned char uc;
    unsigned short us; unsigned int ui; unsigned long ul; void *vp; };
struct tf_empty { };
union tf_u2 { int i; char c; };
enum tf_e2 { TF_X = 7 };
struct tf_withu { union tf_u u; enum tf_e e; int arr[2]; };
struct tf_wide { __int128 s128; unsigned __int128 u128; char tail; };
struct tf_wide tf_wide_v;
struct tf_sub8 *tf_sub8_p; struct tf_arr *tf_arr_p; struct tf_huge *tf_huge_p;
struct tf_bits *tf_bits_p; struct tf_flt *tf_flt_p; struct tf_wide *tf_wide_p;
struct tf_pair *tf_pair_p;
const void *tf_cvp; union tf_u *tf_u_p;
volatile struct tf_pair tf_vol; const struct tf_pair tf_cst;
struct tf_pair *restrict tf_rp;
struct tf_anon { int a; union { int u1; long u2; }; };
struct tf_anon tf_anon_v;
struct tf_anon2 { long a; union { int u1; long u2; }; union { char c1; short c2; }; };
struct tf_anon2 tf_anon2_v;
struct tf_rep { int a; int b; }; struct tf_rep tf_rep_v;
const char *tf_ccp;
typedef struct tf_pair tf_bigarr_t[0x20000000];
tf_bigarr_t *tf_bigarr_p;
struct tf_small tf_small_v; struct tf_big tf_big_v; struct tf_pair tf_pair_v;
union tf_u tf_u_v; enum tf_e tf_e_v; struct tf_bits tf_bits_v;
struct tf_huge tf_huge_v; struct tf_flt tf_flt_v; struct tf_arr tf_arr_v;
struct tf_fwdholder tf_fwdholder_v; struct thread tf_thread_v;
struct tf_undefholder tf_undefholder_v;
tf_pair_t tf_pair_t_v; struct tf_nested tf_nested_v; struct tf_sub8 tf_sub8_v;
struct tf_empty tf_empty_v; union tf_u2 tf_u2_v; enum tf_e2 tf_e2_v;
struct tf_withu tf_withu_v;
''',
    # The definition of typingfix's forward declaration, and same-named
    # structures with identical layouts in a second container.
    'typingfix2': r'''
struct tf_fwd { int fa; long fb; };
struct tf_pair { int a; long b; };
struct tf_big { int a; long b; char c; };
union tf_u { int i; long l; };
enum tf_e { TF_A, TF_B };
struct tf_withu { union tf_u u; enum tf_e e; int arr[2]; };
struct tf_fwd tf_fwd_v; struct tf_pair tf_pair2_v; struct tf_big tf_big2_v;
struct tf_withu tf_withu2_v;
struct tf_rep { int a; long b; }; struct tf_rep tf_rep2_v;
''',
    # Identical layouts again, but with the member types numbered
    # differently inside the container (char/short come first), and
    # same-named structures whose layouts differ from typingfix's.
    'typingfix3': r'''
char tf3_c; short tf3_s; unsigned char tf3_uc;
struct tf_pair { int a; long b; };
struct tf_big { int a; long b; };
union tf_u { int i; short s; };
enum tf_e { TF_A, TF_B, TF_C };
struct tf_small { long a; };
struct tf_small tf_small3_v;
struct tf_pair tf_pair3_v; struct tf_big tf_big3_v; union tf_u tf_u3_v;
enum tf_e tf_e3_v;
struct tf_nested *tf3_nestedp; /* a forward declaration here */
''',
    # A kernel whose CTF lacks the types the type checker asks for (no
    # integer types at all), but has the lock structures.
    'kernelmin': r'''
struct mtx { char m; }; struct rwlock { char r; }; struct sx { char s; };
struct mtx *kmin_mtx; struct rwlock *kmin_rw; struct sx *kmin_sx;
char *kmin_p;
typedef struct mblk { char b; } mblk_t;
mblk_t *kmin_mblk;
''',
    # A module without CTF (built without ctfconvert).
    'typingnoctf': r'''
int typingnoctf_v;
''',
    # The illumos types some D subroutines are declared with.
    'kernelillumos': r'''
typedef unsigned long size_t;
typedef struct mblk { char b; } mblk_t;
typedef struct file { char f; } file_t;
size_t kil_sz; mblk_t *kil_mblk; file_t *kil_file;
''',
}

SHIM = r'''
/* Test boundary: the module inventory comes from TYPING_KLD
 * ("name=path;name=path"), never from the running kernel. */
#include <sys/param.h>
#include <sys/linker.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static int
nth(int id, char *name, char *path)
{
	const char *s = getenv("TYPING_KLD");
	for (int i = 1; s != NULL && *s != '\0'; i++) {
		const char *e = strchr(s, ';');
		size_t l = e ? (size_t)(e - s) : strlen(s);
		if (i == id) {
			char buf[2 * MAXPATHLEN];
			char *eq;
			if (l >= sizeof(buf))
				return (-1);
			memcpy(buf, s, l);
			buf[l] = '\0';
			if ((eq = strchr(buf, '=')) == NULL)
				return (-1);
			*eq = '\0';
			strlcpy(name, buf, MAXPATHLEN);
			strlcpy(path, eq + 1, MAXPATHLEN);
			return (0);
		}
		if (e == NULL)
			break;
		s = e + 1;
	}
	return (-1);
}
int
kldnext(int id)
{
	char n[MAXPATHLEN], p[MAXPATHLEN];
	return (nth(id + 1, n, p) == 0 ? id + 1 : 0);
}
int
kldstat(int id, struct kld_file_stat *st)
{
	char name[MAXPATHLEN], path[MAXPATHLEN];
	if (nth(id, name, path) != 0) {
		errno = ENOENT;
		return (-1);
	}
	/* "name=@fail": listed by kldnext() but kldstat() fails. */
	if (strcmp(path, "@fail") == 0) {
		errno = EIO;
		return (-1);
	}
	strlcpy(st->name, name, sizeof(st->name));
	strlcpy(st->pathname, path, sizeof(st->pathname));
	st->refs = 1;
	st->id = id;
	st->address = (caddr_t)(uintptr_t)(0xffffffff80000000ULL +
	    (uint64_t)id * 0x10000000ULL);
	st->size = 0x1000000;
	return (0);
}
'''

HARNESSES = ['typing-inference', 'typing-units', 'typing-rules', 'typing-reject',
             'typing-args', 'typing-kernelenv', 'typing-progerr', 'typing-roundtrip', 'typing-casts', 'typing-vprog',
             'typing-linktype']
# Runs with another module inventory: (harness, run name, kernel fixture or
# None for no kernel at all, extra environment).
ENV_RUNS = [('typing-kernelenv', 'min', 'kernelmin', {}),
            ('typing-kernelenv', 'illumos', 'kernelillumos', {}),
            ('typing-kernelenv', 'none', None, {}),
            ('typing-kernelenv', 'kldfail', 'kernel', {'TYPING_KLD_EXTRA': 'broken=@fail'}),
            ('typing-kernelenv', 'missing', 'kernel',
             {'TYPING_KLD_EXTRA': 'bogus=/nonexistent/bogus.ko'}),
            ('typing-rules', 'logging', 'kernel', {'TYPING_LOG': '1'}),
            ('typing-inference', 'logging', 'kernel', {'TYPING_LOG': '1'})]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    out, world = (Path(a).resolve() for a in sys.argv[1:])
    if not all(p.is_relative_to('/usr/obj') for p in (out, world)) or out.exists():
        raise SystemExit('Use a new /usr/obj output directory and an existing object tree')
    out.mkdir(parents=True)
    tests = Path(__file__).resolve().parent
    root = tests.parents[2]
    library = world / 'cddl/lib/libdtrace/libdtrace.so.2'
    kernel = Path('/boot/kernel/kernel')
    src_inc = world.parents[3] / 'source-includes'
    if not src_inc.exists():
        src_inc = Path('/usr/obj/5BSD-hypertrace-validation/coverage-compiler-20261020/source-includes')
    common = root / 'cddl/contrib/opensolaris/lib/libdtrace/common'
    objs = {}
    for name, text in FIXTURES.items():
        c = out / (name + '.c')
        c.write_text(text)
        o = out / (name + '.o')
        subprocess.run(['cc', '-c', '-g', '-O0', str(c), '-o', str(o)], check=True)
        if name != 'typingnoctf':
            subprocess.run(['ctfconvert', '-L', 'typing-fixture', str(o)], check=True)
        objs[name] = o
    (out / 'kldshim.c').write_text(SHIM)
    subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                    str(out / 'kldshim.c'), '-o', str(out / 'kldshim.so')], check=True)
    # The process birth identity for the dtraced client handshake.
    subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(root / 'sys'), str(tests / 'dtraced-client-shim.c'),
                    '-o', str(out / 'birthshim.so')], check=True)
    flags = ['-std=c++20', '-g', '-O0', '-Wall', '-Wextra', '-Werror',
             '-Wno-unknown-pragmas', '-Wno-unused-parameter',
             '-Wno-missing-field-initializers',
             '-I' + str(src_inc), '-I' + str(root / 'sys'), '-I' + str(common),
             '-I' + str(root / 'cddl/contrib/opensolaris/lib/libctf/common'),
             '-I' + str(root / 'cddl/contrib/opensolaris/head'),
             '-I' + str(root / 'sys/cddl/compat/opensolaris'),
             '-I' + str(root / 'cddl/compat/opensolaris/include'),
             '-I' + str(root / 'sys/cddl/contrib/opensolaris/uts/common'),
             '-I' + str(root / 'usr.sbin/dtraced')]
    libs = ['-L' + str(world / 'cddl/lib/libdtrace'), '-L' + str(world / 'cddl/lib/libctf'),
            '-L' + str(world / 'lib/libexecinfo'),
            '-Wl,-rpath,' + str(world / 'cddl/lib/libdtrace'),
            '-ldtrace', '-lctf', '-lexecinfo', '-lpthread']
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = ':'.join(str(world / p) for p in
        ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
    env['LD_PRELOAD'] = str(out / 'kldshim.so') + ':' + str(out / 'birthshim.so')
    modules = [f'{n}={o}' for n, o in objs.items() if n.startswith('typing')]
    env['TYPING_KLD'] = ';'.join([f'kernel={kernel}'] + modules)
    env['TYPING_INVENTORY'] = 'full'
    env['TYPING_FIXTURES'] = str(out)
    env['TMPDIR'] = str(out)
    results = []

    def run(h, name, run_env):
        try:
            r = subprocess.run([str(out / h)], env=run_env, cwd=out,
                               capture_output=True, text=True, timeout=3600)
            text, status = r.stdout + r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            text, status = 'timeout', 'timeout'
        (out / (name + '.log')).write_text(text)
        cases = [l for l in text.splitlines() if l.startswith(('PASS: ', 'FAIL: '))]
        results.append({'harness': name, 'status': status,
                        'passed': sum(l.startswith('PASS: ') for l in cases),
                        'failed': [l[6:] for l in cases if l.startswith('FAIL: ')]})

    built = set()
    for h in HARNESSES:
        source = tests / (h + '.cc')
        build = subprocess.run(['c++', *flags, str(source), *libs, '-o', str(out / h)],
                               capture_output=True, text=True)
        (out / (h + '.build.log')).write_text(build.stdout + build.stderr)
        if build.returncode:
            results.append({'harness': h, 'status': 'build-failed'})
            continue
        built.add(h)
        if h != 'typing-kernelenv':
            run(h, h, env)
    for h, name, kmod, extra in ENV_RUNS:
        if h not in built:
            continue
        e = env | extra
        kpath = kernel if kmod == 'kernel' else objs.get(kmod)
        e['TYPING_KLD'] = ';'.join(([f'kernel={kpath}'] if kpath else []) +
                                   [f'{n}={o}' for n, o in objs.items()
                                    if n.startswith('typing')] +
                                   ([extra['TYPING_KLD_EXTRA']]
                                    if 'TYPING_KLD_EXTRA' in extra else []))
        e['TYPING_INVENTORY'] = name
        run(h, f'{h}-{name}', e)
    # Consumers that do not call hypertrace_link(): lockstat and plockstat,
    # built from their own sources with tool-dof-shim.c, run to the DOF
    # their dtrace_program_exec() hands the kernel.  No DIF in it may hold a
    # link-time instruction (TYPECAST, USETX, ULOAD, UULOAD: the kernel's
    # DIF validator refuses them), and the compiled program must have held
    # some (else the check is vacuous).
    tool_runs = [('lockstat', a) for a in ([], ['-H'], ['-A', '-s', '8'], ['-C', '-t'],
                                         ['-h', '-s', '4'], ['-I'], ['-E'], ['-T'])] + \
                [('plockstat', a) for a in ([], ['-H'], ['-C'], ['-s', '8'])]
    osrc = root / 'cddl/contrib/opensolaris'
    zfs = root / 'sys/contrib/openzfs'
    tinc = ['-DIN_BASE', '-DSKIP_SPL_SYS_CONDVAR_H', '-DHAVE_ISSETUGID', '-DNEED_ERRLOC',
            '-I' + str(src_inc), '-I' + str(zfs / 'include'),
            '-I' + str(zfs / 'lib/libspl/include'),
            '-I' + str(zfs / 'lib/libspl/include/os/freebsd'), '-I' + str(root / 'sys'),
            '-I' + str(root / 'cddl/compat/opensolaris/include'),
            '-I' + str(root / 'sys/cddl/compat/opensolaris'), '-I' + str(osrc / 'head'),
            '-I' + str(common), '-I' + str(osrc / 'lib/libctf/common'),
            '-I' + str(osrc / 'lib/libproc/common'),
            '-I' + str(root / 'sys/cddl/contrib/opensolaris/uts/common'),
            '-I' + str(root / 'sys/cddl/contrib/opensolaris/compat'),
            '-I' + str(root / 'cddl/lib/libdtrace'), '-I' + str(root / 'lib/libproc')]
    tlibs = ['-L' + str(world / 'cddl/lib/libdtrace'), '-L' + str(world / 'cddl/lib/libctf'),
             '-L' + str(world / 'lib/libproc'), '-L' + str(world / 'lib/librtld_db'),
             '-Wl,-rpath,' + str(world / 'cddl/lib/libdtrace'),
             '-ldtrace', '-lctf', '-lproc', '-lelf', '-lrt', '-lpthread']
    wraps = ['-Wl,--wrap=' + f for f in ('symtab_init', 'dtrace_open',
                                          'dtrace_program_strcompile', 'dtrace_proc_create')]
    tool_srcs = {'lockstat': [osrc / 'cmd/lockstat/lockstat.c', osrc / 'cmd/lockstat/sym.c'],
                 'plockstat': [osrc / 'cmd/plockstat/plockstat.c']}
    tool_results = []
    tbuild = subprocess.run(['cc', '-g', '-w', *tinc, '-c', str(tests / 'tool-dof-shim.c'),
                             '-o', str(out / 'tool-dof-shim.o')], capture_output=True, text=True)
    for tool, srcs in tool_srcs.items():
        if tbuild.returncode == 0:
            tbuild = subprocess.run(['cc', '-g', '-w', *tinc, *map(str, srcs),
                                     str(out / 'tool-dof-shim.o'), *wraps, *tlibs,
                                     '-o', str(out / tool)], capture_output=True, text=True)
        (out / (tool + '.build.log')).write_text(tbuild.stdout + tbuild.stderr)
    if tbuild.returncode:
        results.append({'harness': 'tool-dof', 'status': 'build-failed'})
    else:
        tenv = env | {'TYPING_KLD': f'kernel={kernel}'}
        failed, passed = [], 0
        for tool, args in tool_runs:
            name = ' '.join([tool, *args])
            try:
                r = subprocess.run([str(out / tool), *args, 'true'], env=tenv, cwd=out,
                                   capture_output=True, text=True, timeout=600)
                text = r.stdout + r.stderr
            except subprocess.TimeoutExpired:
                text = 'timeout'
            m = re.search(r'TOOLDOF difos=(\d+) instrs=(\d+) typecast=(\d+) usetx=(\d+) '
                          r'uload=(\d+) uuload=(\d+) annotations=(\d+)', text)
            row = {'run': name, 'output': text[-400:]}
            if m:
                row.update(dict(zip(('difos', 'instrs', 'typecast', 'usetx', 'uload',
                                     'uuload', 'annotations'), map(int, m.groups()))))
            ok = m is not None and row['difos'] > 0 and row['annotations'] > 0 and \
                all(row[k] == 0 for k in ('typecast', 'usetx', 'uload', 'uuload'))
            tool_results.append(row | {'passed': ok})
            if ok:
                passed += 1
            else:
                failed.append(name)
        (out / 'tool-dof.json').write_text(json.dumps(tool_results, indent=2) + '\n')
        results.append({'harness': 'tool-dof', 'status': 0 if not failed else 1,
                        'passed': passed, 'failed': failed})
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    sources = [Path(__file__).resolve()] + [tests / (h + '.cc') for h in HARNESSES] + \
        [tests / 'typing-harness.h', tests / 'typing-oracle.h', tests / 'typing-unit.h',
         tests / 'dtraced-client-shim.c', tests / 'tool-dof-shim.c'] + \
        [p for v in tool_srcs.values() for p in v]
    (out / 'provenance.json').write_text(json.dumps({
        'sha256': {str(p): sha(p) for p in [library, kernel, *sources]},
        'fixtures_sha256': {str(o): sha(o) for o in objs.values()},
        'module_inventory': env['TYPING_KLD'],
        'device_mode': 'DTRACE_O_NODEV; kldnext/kldstat interposed',
        'separate_process_per_case': True, 'live': False}, indent=2) + '\n')
    bad = [r for r in results if r['status'] != 0]
    for r in bad:
        print(json.dumps(r))
    if bad:
        raise SystemExit(1)
    total = sum(r['passed'] for r in results)
    print(f'PASS: {total} HyperTrace typing/linker cases in {len(results)} harnesses')


if __name__ == '__main__':
    main()
