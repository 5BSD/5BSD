#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Measure the actual dtrace(1) executable and the drti runtime object.

usage: coverage-cli.py OUTPUT [--objtop OBJTOP] [--suite NAME ...]

The executable is rebuilt from the maintained cddl/usr.sbin/dtrace make
commands (captured with make -n against the shared coverage object tree, then
run in OUTPUT/build with the coverage compiler wrappers).  The shared
libdtrace, libctf, libproc and librtld_db builds are used read-only.

Every executed case runs the real binary.  The preload shim in
cli-model-shim.c is the only boundary: dtrace_open() is redirected either to
the real NODEV|NOSYS open (compile/link/header modes) or to dtrace_vopen() with
the audited dtrace(4) model, connect() to the dtraced socket is redirected to a
private fake daemon, and every tracing/helper device path is refused.  Faults
are injected only through the shim's counters, and each injected fault is
recorded so a case can assert it actually fired.

Reported figures use complete mapped source denominators.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import resource
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
TESTS = Path(__file__).resolve().parent
DEFAULT_OBJTOP = Path('/usr/obj/5BSD-hypertrace-validation/coverage-compiler-20261020'
                      '/usr/obj/5BSD-hypertrace/amd64.amd64')
WRAPPERS = Path('/usr/obj/5BSD-hypertrace-validation/coverage-runner-check-20261020/bin')
CLI_SRC = ROOT/'cddl/contrib/opensolaris/cmd/dtrace'
PRODUCTION = [CLI_SRC/'dtrace.c', CLI_SRC/'dtrace_identifiers.h', CLI_SRC/'hypertrace_frame.h',
              ROOT/'usr.sbin/dtraced/dtraced_io.h', ROOT/'usr.sbin/dtraced/dtraced_wire.h',
              ROOT/'cddl/contrib/opensolaris/lib/libdtrace/common/drti.c']


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def maintained_commands(objtop):
    """Capture the maintained build's compile/link commands."""
    prefix = str(objtop).split('/usr/obj/5BSD-hypertrace/')[0]
    env = {k: v for k, v in os.environ.items() if k != 'CXXFLAGS'}
    env.update(PATH=f'{WRAPPERS}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
               MAKEOBJDIRPREFIX=prefix,
               CFLAGS=f'-O0 -g -pipe -I{prefix}/source-includes')
    proc = subprocess.run(['make', '-n', '-B', '-C', str(ROOT/'cddl/usr.sbin/dtrace'),
                           '-m', str(ROOT/'share/mk'), f'SRCTOP={ROOT}', 'SRCCONF=/dev/null',
                           '__MAKE_CONF=/dev/null', 'all'],
                          env=env, capture_output=True, text=True, check=True)
    # Dependency bookkeeping for the shared object directory (.depend) is not
    # part of producing the executable; only compiler and objcopy steps run.
    commands = [line for line in proc.stdout.splitlines()
                if line.startswith(('cc ', 'objcopy '))]
    if not commands or 'dtrace.c' not in commands[0] or \
            [c.split()[0] for c in commands] != ['cc', 'cc', 'objcopy', 'objcopy']:
        raise SystemExit('unexpected maintained build commands:\n' + proc.stdout)
    return env, commands


def snapshot_libraries(objtop, snap):
    for rel, pattern in (('cddl/lib/libdtrace', 'libdtrace.so.2'),
                         ('cddl/lib/libctf', 'libctf.so.2'), ('lib/libproc', 'libproc.so.5'),
                         ('lib/librtld_db', 'librtld_db.so.*'), ('cddl/lib/drti', 'drti.o')):
        (snap/rel).mkdir(parents=True)
        for source in sorted((objtop/rel).glob(pattern)):
            for _ in range(10):
                digest = sha(source)
                shutil.copyfile(source, snap/rel/source.name)
                if sha(snap/rel/source.name) == digest == sha(source):
                    break
            else:
                raise SystemExit(f'{source} keeps changing; cannot snapshot it')
            (snap/rel/source.name).chmod(0o755)
    (snap/'cddl/lib/libdtrace/libdtrace.so').symlink_to('libdtrace.so.2')
    return snap


def build(out, objtop, libtop):
    build_dir = out/'build'
    build_dir.mkdir()
    env, commands = maintained_commands(objtop)
    (out/'build-commands.txt').write_text('\n'.join(commands) + '\n')
    with (out/'build.log').open('w') as log:
        for command in commands:
            log.write('$ ' + command + '\n')
            log.flush()
            subprocess.run(command, shell=True, cwd=build_dir, env=env, stdout=log,
                           stderr=subprocess.STDOUT, check=True)
    binary = build_dir/'dtrace'
    if not binary.is_file():
        raise SystemExit('maintained build produced no dtrace executable')
    # A symlink object tree lets the unmodified historical cli-offline.py run
    # this binary with the shared (read-only) libraries.
    farm = out/'objtop'
    for rel in ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db',
                'cddl/lib/drti'):
        (farm/rel).parent.mkdir(parents=True, exist_ok=True)
        (farm/rel).symlink_to(libtop/rel)
    (farm/'cddl/usr.sbin/dtrace').mkdir(parents=True)
    (farm/'cddl/usr.sbin/dtrace/dtrace').symlink_to(binary)
    return binary


def runtime_env(objtop, profile_dir):
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = ':'.join(str(objtop/p) for p in
                                      ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc',
                                       'lib/librtld_db'))
    env['LLVM_PROFILE_FILE'] = str(profile_dir/'%p-%m.profraw')
    return env


def merge_export(out, name, profiles, binary):
    raw = sorted(p for d in profiles for p in Path(d).glob('*.profraw'))
    if not raw:
        raise SystemExit(f'{name}: no profiles')
    empty = [str(p) for p in raw if p.stat().st_size == 0]
    if empty:
        raise SystemExit(f'{name}: empty profiles {empty[:5]}')
    listing = out/f'{name}-profiles.txt'
    listing.write_text('\n'.join(map(str, raw)) + '\n')
    merged = out/f'{name}.profdata'
    with (out/f'{name}-merge.log').open('w') as log:
        subprocess.run(['llvm-profdata', 'merge', '-sparse', '-f', str(listing), '-o',
                        str(merged)], stdout=log, stderr=subprocess.STDOUT, check=True)
    if (out/f'{name}-merge.log').read_text().strip():
        raise SystemExit(f'{name}: llvm-profdata diagnostics')
    export = out/f'{name}-coverage.json'
    with export.open('w') as stdout, (out/f'{name}-export.log').open('w') as stderr:
        subprocess.run(['llvm-cov', 'export', str(binary), '-instr-profile=' + str(merged)],
                       stdout=stdout, stderr=stderr, check=True)
    if (out/f'{name}-export.log').read_text().strip():
        raise SystemExit(f'{name}: llvm-cov export diagnostics')
    return json.loads(export.read_text())['data'][0], len(raw)


def upstream_functions():
    """Function names in the FreeBSD dtrace.c at HEAD (pre-HyperTrace)."""
    text = subprocess.run(['git', '-C', str(ROOT), 'show',
                           'HEAD:cddl/contrib/opensolaris/cmd/dtrace/dtrace.c'],
                          capture_output=True, text=True, check=True).stdout
    names = set()
    for line in text.splitlines():
        if line[:1].isalpha() and '(' in line and not line.startswith(('static', 'typedef')):
            head = line.split('(')[0]
            if head.replace('_', '').isalnum():
                names.add(head)
    return names


def summarize(data, label):
    rows = {}
    for f in data['files']:
        path = Path(f['filename'])
        if path in PRODUCTION or path.resolve() in PRODUCTION:
            s = f['summary']
            rows[str(path)] = {k: {'covered': s[k]['covered'], 'count': s[k]['count'],
                                   'percent': round(s[k]['percent'], 4)}
                               for k in ('lines', 'branches', 'functions', 'regions')}
            rows[str(path)]['sha256'] = sha(path)
    return {'label': label, 'files': rows}


def function_report(binary, profdata, out, name):
    """Per-function lines/branches exactly as llvm-cov reports them."""
    proc = subprocess.run(['llvm-cov', 'report', '-show-functions',
                           '-instr-profile=' + str(profdata), str(binary),
                           str(CLI_SRC/'dtrace.c')], capture_output=True, text=True, check=True)
    if proc.stderr.strip():
        raise SystemExit(f'{name}: llvm-cov report diagnostics: {proc.stderr}')
    (out/f'{name}-functions.txt').write_text(proc.stdout)
    rows = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) != 10 or not parts[1].isdigit() or parts[0] == 'TOTAL':
            continue
        fname = parts[0].split(':')[-1]
        rows[fname] = {'regions': (int(parts[1]) - int(parts[2]), int(parts[1])),
                       'lines': (int(parts[4]) - int(parts[5]), int(parts[4])),
                       'branches': (int(parts[7]) - int(parts[8]), int(parts[7]))}
    return rows


def origin_split(rows):
    """Sum per-function rows by origin (HyperTrace-added vs FreeBSD)."""
    upstream = upstream_functions()
    totals = {}
    for origin in ('hypertrace', 'freebsd'):
        chosen = {n: r for n, r in rows.items() if (n in upstream) == (origin == 'freebsd')}
        totals[origin] = {k: [sum(r[k][0] for r in chosen.values()),
                              sum(r[k][1] for r in chosen.values())]
                          for k in ('lines', 'branches', 'regions')}
        totals[origin]['functions'] = [sum(1 for r in chosen.values() if r['regions'][0] > 0),
                                       len(chosen)]
        totals[origin]['names'] = sorted(chosen)
    return totals


def build_harness(out, objtop, libtop):
    """Compile the preload shim and fake daemon (never instrumented)."""
    harness = out/'harness'
    harness.mkdir()
    prefix = Path(str(objtop).split('/usr/obj/5BSD-hypertrace/')[0])
    snapshot = harness/'consume-ingestion.c'
    shutil.copyfile(TESTS/'consume-ingestion.c', snapshot)
    common = ROOT/'cddl/contrib/opensolaris/lib/libdtrace/common'
    includes = [harness, prefix/'source-includes', ROOT/'sys', common,
                ROOT/'cddl/contrib/opensolaris/lib/libctf/common',
                ROOT/'cddl/contrib/opensolaris/head', ROOT/'sys/cddl/compat/opensolaris',
                ROOT/'cddl/compat/opensolaris/include',
                ROOT/'sys/cddl/contrib/opensolaris/uts/common']
    shim = harness/'cli-model-shim.so'
    commands = [
        ['/usr/bin/cc', '-std=gnu17', '-g', '-O0', '-fPIC', '-shared', '-Wall', '-Werror',
         '-Wno-unused-function', '-Wno-unused-variable', '-Wno-unused-but-set-variable',
         *('-I' + str(p) for p in includes), str(TESTS/'cli-model-shim.c'),
         '-L' + str(libtop/'cddl/lib/libdtrace'), '-ldtrace', '-lxo', '-lelf', '-o', str(shim)],
        ['/usr/bin/cc', '-std=gnu17', '-g', '-O0', '-Wall', '-Werror', '-pthread',
         '-I' + str(ROOT/'usr.sbin/dtraced'), '-I' + str(ROOT/'sys'),
         str(TESTS/'cli-fake-dtraced.c'), '-lcrypto', '-o', str(harness/'cli-fake-dtraced')],
    ]
    # Field offsets of the on-disk dt_elf_prog_t, used to read a program's
    # source identifier from a derived ELF for the -N handshake.
    (harness/'elf-offsets.c').write_text(
        '#include <stddef.h>\n#include <stdio.h>\n#include <dt_elf.h>\n'
        'int main(void) { printf("%zu %zu %d\\n", offsetof(dt_elf_prog_t, dtep_srcident),'
        ' offsetof(dt_elf_prog_t, dtep_exec), (int)DT_PROG_IDENTLEN); return (0); }\n')
    commands.append(['/usr/bin/cc', *('-I' + str(p) for p in includes),
                     str(harness/'elf-offsets.c'), '-o', str(harness/'elf-offsets')])
    with (out/'harness-build.log').open('w') as log:
        for command in commands:
            log.write('$ ' + shlex.join(command) + '\n')
            log.flush()
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    offsets = subprocess.run([str(harness/'elf-offsets')], capture_output=True, text=True,
                             check=True).stdout.split()
    return {'shim': shim, 'daemon': harness/'cli-fake-dtraced', 'snapshot': snapshot,
            'srcident_offset': int(offsets[0]), 'exec_offset': int(offsets[1]),
            'identlen': int(offsets[2]),
            'sha256': {str(p): sha(p) for p in (TESTS/'cli-model-shim.c',
                       TESTS/'cli-fake-dtraced.c', snapshot, TESTS/'consume-ingestion.c')}}


def load_cases():
    import importlib.util
    spec = importlib.util.spec_from_file_location('cli_cases', TESTS/'coverage-cli-cases.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Frozen full-file denominators and regression floors (lines, branches,
# functions as covered/count), reviewed after wiring -x checkmodref
# (cov-cli-modref-20261021: 3139/3309, 1520/1745, 80/80), then reviewed
# after link_failed() (program errors returned by libdtrace, case
# exec-program-type-error; lib-typing-20261021/cli-c: 3150/3315, 1525/1747,
# 81/81), then reviewed after -y was made to run its ELF and exit instead of
# falling into the host consumer path (cli-dec3, 2026-10-22: 3167/3341,
# 1534/1761, 81/81; the host-path arms -y used to reach are now reached only
# by -E).  A changed denominator needs an explicit baseline review; floors
# allow a small tolerance for interleaving-dependent paths (session-stop exits
# in the worker).
REGRESSION = {
    'dtrace.c': {'lines': (3157, 3341), 'branches': (1524, 1761), 'functions': (81, 81)},
    'dtrace_identifiers.h': {'lines': (53, 57), 'branches': (33, 46), 'functions': (3, 3)},
    'hypertrace_frame.h': {'lines': (47, 48), 'branches': (47, 60), 'functions': (2, 2)},
}


def regression_checks(files):
    checks, ok = {}, True
    for name, floors in REGRESSION.items():
        row = next((r for p, r in files.items() if Path(p).name == name), None)
        if row is None:
            checks[name] = {'error': 'not mapped'}
            ok = False
            continue
        checks[name] = {}
        for metric, (floor, count) in floors.items():
            got = row[metric]
            passed = got['count'] == count and got['covered'] >= floor
            ok = ok and passed
            checks[name][metric] = {'covered': got['covered'], 'count': got['count'],
                                    'floor': floor, 'expected_count': count,
                                    'regression_passed': passed,
                                    'target_97_met': got['covered'] * 100 >= got['count'] * 97}
    return checks, ok


GENERATED = {
    # generated file -> (maintained inputs, generator)
    'dt_grammar.c': (['cddl/contrib/opensolaris/lib/libdtrace/common/dt_grammar.y'], 'yacc'),
    'dt_lex.c': (['cddl/contrib/opensolaris/lib/libdtrace/common/dt_lex.l'], 'lex'),
    'dt_errtags.c': (['cddl/contrib/opensolaris/lib/libdtrace/common/dt_errtags.h',
                      'cddl/contrib/opensolaris/lib/libdtrace/common/mkerrtags.sh'], 'sh'),
    'dt_names.c': (['sys/cddl/contrib/opensolaris/uts/common/sys/dtrace.h',
                    'cddl/contrib/opensolaris/lib/libdtrace/common/mknames.sh'], 'sh'),
}


def line_map(path):
    """Physical line -> (file, line) from #line directives (None: directive)."""
    mapping = {}
    current = (str(path), 0)
    for number, text in enumerate(Path(path).read_text(errors='replace').splitlines(), 1):
        if text.startswith('#line '):
            parts = text.split(None, 2)
            target = parts[2].strip().strip('"') if len(parts) > 2 else current[0]
            if not target.startswith('/'):
                target = str(Path(path).parent/target)
            current = (target, int(parts[1]) - 1)
            mapping[number] = None
            continue
        current = (current[0], current[1] + 1)
        mapping[number] = current
    return mapping


def attribute_generated(evidence, objtop, out):
    """Attribute generated compiler sources back to their inputs (read-only)."""
    libdir = objtop/'cddl/lib/libdtrace'
    library = libdir/'libdtrace.so.2'
    summary = json.loads((evidence/'summary.json').read_text())
    if summary.get('binary_sha256') != sha(library):
        raise SystemExit('library evidence does not match the current libdtrace.so.2')
    sources = {name: libdir/name for name in GENERATED}
    for name, path in sources.items():
        recorded = summary.get('source_sha256', {}).get(str(path))
        if recorded is not None and recorded != sha(path):
            raise SystemExit(f'{name} changed since the library evidence was taken')
    lcov = out/'generated.lcov'
    with lcov.open('w') as stdout, (out/'generated-lcov.log').open('w') as stderr:
        subprocess.run(['llvm-cov', 'export', '-format=lcov', str(library),
                        '-instr-profile=' + str(evidence/'passing.profdata'),
                        *map(str, sources.values())], stdout=stdout, stderr=stderr, check=True)
    if (out/'generated-lcov.log').read_text().strip():
        raise SystemExit('llvm-cov lcov diagnostics for generated sources')
    records, current = {}, None
    for rec in lcov.read_text().splitlines():
        if rec.startswith('SF:'):
            current = Path(rec[3:]).name
            records[current] = {'lines': {}, 'branches': []}
        elif rec.startswith('DA:') and current:
            ln, count = rec[3:].split(',')[:2]
            records[current]['lines'][int(ln)] = int(count)
        elif rec.startswith('BRDA:') and current:
            ln, _, _, taken = rec[5:].split(',')
            records[current]['branches'].append((int(ln), taken not in ('-', '0')))
    report = {'evidence': str(evidence), 'library_sha256': sha(library), 'files': {}}
    for name, (inputs, tool) in GENERATED.items():
        data = records.get(name, {'lines': {}, 'branches': []})
        mapping = line_map(sources[name])
        attributed, generated_only = {}, {'lines': [0, 0], 'branches': [0, 0]}
        for ln, count in data['lines'].items():
            target = mapping.get(ln)
            if target is None or Path(target[0]).name == name:
                generated_only['lines'][1] += 1
                generated_only['lines'][0] += count > 0
                continue
            row = attributed.setdefault(target[0], {'lines': {}, 'branches': [0, 0]})
            row['lines'][target[1]] = max(row['lines'].get(target[1], 0), count)
        for ln, taken in data['branches']:
            target = mapping.get(ln)
            if target is None or Path(target[0]).name == name:
                generated_only['branches'][1] += 1
                generated_only['branches'][0] += taken
                continue
            row = attributed.setdefault(target[0], {'lines': {}, 'branches': [0, 0]})
            row['branches'][1] += 1
            row['branches'][0] += taken
        report['files'][name] = {
            'generator': tool, 'inputs': {i: sha(ROOT/i) for i in inputs},
            'generated_sha256': sha(sources[name]),
            'physical_totals': {
                'lines': [sum(1 for c in data['lines'].values() if c > 0), len(data['lines'])],
                'branches': [sum(t for _, t in data['branches']), len(data['branches'])]},
            'attributed': {src: {'lines': [sum(1 for c in r['lines'].values() if c > 0),
                                           len(r['lines'])],
                                 'branches': r['branches'],
                                 'uncovered_source_lines': sorted(
                                     k for k, c in r['lines'].items() if c == 0)}
                           for src, r in attributed.items()},
            'generated_only': generated_only,
            'line_mapping': 'none (table generator)' if not any(
                v is None for v in mapping.values()) else '#line directives'}
    (out/'generated-attribution.json').write_text(json.dumps(report, indent=2) + '\n')
    for name, row in report['files'].items():
        print(name, 'physical', row['physical_totals'], 'generated-only', row['generated_only'])
        for src, r in row['attributed'].items():
            print('   ->', Path(src).name, 'lines', r['lines'], 'branches', r['branches'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('output')
    parser.add_argument('--objtop', default=str(DEFAULT_OBJTOP))
    parser.add_argument('--only', default=None, help='regex of case names to run')
    parser.add_argument('--skip-baseline', action='store_true')
    parser.add_argument('--generated-from', default=None,
                        help='library coverage evidence directory: attribute generated '
                             'compiler sources only (read-only use of that evidence)')
    args = parser.parse_args()
    out = Path(args.output).resolve()
    objtop = Path(args.objtop).resolve()
    if not out.is_relative_to('/usr/obj') or out.exists():
        raise SystemExit('Use a new /usr/obj output directory')
    out.mkdir(parents=True)
    if args.generated_from:
        attribute_generated(Path(args.generated_from).resolve(), objtop, out)
        return
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    before = {str(p): sha(p) for p in PRODUCTION}
    # Run against a private snapshot of the shared libraries so a concurrent
    # rebuild of the shared tree cannot change them mid-run.
    libtop = snapshot_libraries(objtop, out/'libsnap')
    libs = {str(libtop/p): sha(libtop/p) for p in
            ('cddl/lib/libdtrace/libdtrace.so.2', 'cddl/lib/libctf/libctf.so.2',
             'lib/libproc/libproc.so.5', 'cddl/lib/drti/drti.o')}
    binary = build(out, objtop, libtop)
    harness = build_harness(out, objtop, libtop)
    objtop = libtop
    provenance = {'sources': before, 'libraries_read_only': libs, 'binary': str(binary),
                  'binary_sha256': sha(binary), 'driver_sha256': sha(__file__),
                  'cases_sha256': sha(TESTS/'coverage-cli-cases.py'),
                  'harness_sha256': harness['sha256'],
                  'boundary': 'LD_PRELOAD cli-model-shim.so: dtrace_open -> NODEV|NOSYS real '
                              'open or dtrace_vopen(model); dtraced socket -> fake daemon; '
                              'device, /boot and kldload refused; libc faults only for calls '
                              'from the dtrace executable; abort() logged and mapped to '
                              'exit(134)'}
    summary = {}
    profile_dirs = []
    if not args.skip_baseline:
        # Baseline: the unmodified historical suite, against this fresh build.
        base_profiles = out/'profiles-baseline'
        base_profiles.mkdir()
        env = runtime_env(objtop, base_profiles)
        with (out/'baseline-cli-offline.log').open('w') as log:
            rc = subprocess.run([sys.executable, str(TESTS/'cli-offline.py'),
                                 str(out/'baseline-cli-offline'), str(out/'objtop')],
                                env=env, stdout=log, stderr=subprocess.STDOUT,
                                timeout=600).returncode
        provenance['baseline_cli_offline_status'] = rc
        provenance['cli_offline_sha256'] = sha(TESTS/'cli-offline.py')
        if rc != 0:
            raise SystemExit('baseline cli-offline.py failed; see baseline-cli-offline.log')
        data, nprof = merge_export(out, 'baseline', [base_profiles], binary)
        rows = function_report(binary, out/'baseline.profdata', out, 'baseline')
        summary['baseline'] = summarize(data, 'cli-offline.py (historical suite), fresh build')
        summary['baseline_functions'] = rows
        summary['baseline_origin_split'] = origin_split(rows)
        summary['baseline_profiles'] = nprof
        profile_dirs.append(base_profiles)
    cases = load_cases()
    case_profiles = out/'profiles-cases'
    case_profiles.mkdir()
    env = runtime_env(objtop, case_profiles)
    results = cases.run_all(out, binary, harness, env, objtop, args.only)
    (out/'results.json').write_text(json.dumps(results, indent=2) + '\n')
    failed = [r for r in results if not r['passed']]
    passing = [r for r in results if r['passed']]
    # Only profiles of passing cases are merged; failures stay for audit.
    keep = out/'profiles-passing'
    keep.mkdir()
    excluded = []
    for r in passing:
        # A process killed by a signal (a recorded known defect) may leave
        # partial counter files; such profiles are never merged.
        if r['status'] is not None and r['status'] < 0:
            excluded.append(r['name'])
            continue
        for prof in r['profiles']:
            shutil.copyfile(prof, keep/Path(prof).name)
    profile_dirs.append(keep)
    if not any(any(Path(d2).glob('*.profraw')) for d2 in profile_dirs):
        for r in failed:
            print('FAILED', r['name'], '; '.join(r['errors'])[:2000])
        raise SystemExit('no passing profiles to merge')
    data, nprof = merge_export(out, 'combined', profile_dirs, binary)
    rows = function_report(binary, out/'combined.profdata', out, 'combined')
    summary['combined'] = summarize(data, 'historical suite + coverage-cli-cases (passing)')
    summary['combined_functions'] = rows
    summary['combined_origin_split'] = origin_split(rows)
    summary['combined_profiles'] = nprof
    summary['cases'] = {'passed': len(passing), 'failed': len(failed),
                        'failed_names': [r['name'] for r in failed],
                        'profiles_excluded_signal_exit': excluded,
                        'known_defects': sorted({r['known_defect'] for r in results
                                                 if r.get('known_defect')})}
    summary['regression'], regression_ok = regression_checks(summary['combined']['files'])
    after = {str(p): sha(p) for p in PRODUCTION}
    if after != before:
        raise SystemExit('production sources changed during the run')
    if {p: sha(p) for p in libs} != libs:
        raise SystemExit('a shared library changed during the run; results are not usable')
    (out/'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    (out/'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    if not regression_ok:
        print('REGRESSION', json.dumps(summary['regression']))
        failed = failed or [{'name': 'regression-gate', 'errors': ['coverage regression']}]
    for label in ('baseline', 'combined'):
        if label not in summary:
            continue
        for path, row in summary[label]['files'].items():
            print(label, Path(path).name, {k: (v['covered'], v['count'])
                                           for k, v in row.items() if isinstance(v, dict)})
        for origin, row in summary[label + '_origin_split'].items():
            print(label, origin, {k: v for k, v in row.items() if k != 'names'})
    for r in failed:
        print('FAILED', r['name'], '; '.join(r['errors'])[:2000])
    print(f'{len(passing)}/{len(results)} executable cases passed')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
