#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Measure dtraced and dtracedctl coverage with whole-file production denominators.

Offline only: no installed daemon, tracing device, VM or module is used.

Collections (each run writes a new cov-daemon-* directory under /usr/obj):
  daemon   native-daemon.py component suites plus daemon-extra.py suites. Both
           link the unmodified daemon objects (sanitized DTRACED_NATIVE_TEST
           build); neither starts an installed daemon.
  ctl      the maintained usr.sbin/dtracedctl make target run by
           control-cli-offline.py against independent Unix-socket peers.

Denominators
  * Every daemon/control source and header is listed in summary.json; a file
    no binary maps stays visible with its physical line count.
  * A header-denominator object includes every production header and is
    compiled with -femit-all-decls, so unused inline helpers contribute their
    full line/branch mapping instead of a reduced "unused function" mapping.
  * llvm-cov silently drops a function whose name exists in the profile with
    a different structural hash (for example production main versus test
    mains). Each measured export is therefore audited against an
    --empty-profile export of the same objects; dropped mappings are added
    back to the denominator as uncovered and listed by file.

Configurations
  native-test  test-build objects plus every executed suite binary (static
               inline header copies in test translation units are credited to
               the unmodified header).
  production   a production-configuration build of the Makefile SRCS (no
               DTRACED_NATIVE_TEST, no sanitizers), linked but never run. Its
               .cc rows use only production objects, so a function whose
               preprocessed body differs from the test build is uncovered
               there. Header rows are configuration independent (verified:
               headers do not test DTRACED_NATIVE_TEST) and are taken from the
               native-test union.
"""
from pathlib import Path
import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
tests = Path(__file__).resolve().parent
daemon_dir = root / 'usr.sbin/dtraced'
ctl_dir = root / 'usr.sbin/dtracedctl'
FLAGS = ['-fprofile-instr-generate', '-fcoverage-mapping',
         '-fprofile-update=atomic']

parser = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('output', type=Path)
parser.add_argument('--collection', action='append', choices=('daemon', 'ctl'))
parser.add_argument('--skip-native', action='store_true',
                    help='exploratory: do not run native-daemon.py')
parser.add_argument('--extra-suite', action='append', default=[],
                    help='exploratory: restrict daemon-extra.py suites')
args = parser.parse_args()
out = args.output.resolve()
if not out.is_relative_to('/usr/obj/5BSD-hypertrace-validation') or \
        not out.name.startswith('cov-daemon-'):
    parser.error('Use a new /usr/obj/5BSD-hypertrace-validation/cov-daemon-* directory')
if out.exists():
    parser.error('Output must be new; stale counters invalidate evidence')
collections = args.collection or ['daemon', 'ctl']
out.mkdir(parents=True)
ncpu = int(subprocess.check_output(['sysctl', '-n', 'hw.ncpu'], text=True))
exploratory = bool(args.skip_native or (args.extra_suite and args.extra_suite != ['none']))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def production_sources():
    files = sorted(p for p in daemon_dir.iterdir()
                   if p.suffix in ('.cc', '.h') and p.is_file())
    files += sorted(p for p in ctl_dir.iterdir() if p.suffix in ('.c', '.h'))
    return files


sources = production_sources()
source_hashes = {str(p): sha(p) for p in sources}
(out / 'source-before.json').write_text(json.dumps(source_hashes, indent=2) + '\n')
headers = [p for p in sources if p.suffix == '.h' and p.parent == daemon_dir]
assert not any('DTRACED_NATIVE_TEST' in p.read_text() for p in headers)

wrappers = out / 'bin'
wrappers.mkdir()
for compiler in ('cc', 'c++', 'clang', 'clang++'):
    w = wrappers / compiler
    w.write_text('#!/bin/sh\nexec /usr/bin/' + compiler + ' ' + ' '.join(FLAGS) +
                 ' "$@"\n')
    w.chmod(0o755)

provenance = {
    'live_tests': False,
    'exploratory': exploratory,
    'head': subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'],
                                    text=True).strip(),
    'dirty_tree_note': 'HEAD does not identify this dirty tree; use source hashes.',
    'compiler': subprocess.check_output(['/usr/bin/c++', '--version'],
                                        text=True).splitlines()[0],
    'llvm_cov': subprocess.check_output(['llvm-cov', '--version'],
                                        text=True).strip().splitlines()[-1],
    'coverage_flags': FLAGS,
    'collections': collections,
    'skip_native': args.skip_native,
    'extra_suite_filter': args.extra_suite,
    'drivers': {},
    'test_sources': {p.name: sha(p) for p in sorted(tests.glob('*.cc'))},
    'ncpu': ncpu,
}


def run_driver(name, argv, profiles, timeout=10800):
    profiles.mkdir(exist_ok=True)
    env = os.environ.copy()
    env.pop('DTRACED_COVERAGE_SWEEPS', None)  # the live sweeps always run here
    env.update(PATH=str(wrappers) + os.pathsep + env.get('PATH', ''),
               LLVM_PROFILE_FILE=str(profiles / '%m-%p.profraw'),
               HYPERTRACE_COVERAGE_DIR=str(profiles))
    log = out / (name + '.log')
    # Private working directory: a child whose environment drops
    # LLVM_PROFILE_FILE (native-daemon's process-launch child) writes
    # default.profraw into its cwd; keep it out of the worktree and merge it.
    cwd = out / (name + '-cwd')
    cwd.mkdir(exist_ok=True)
    with log.open('w') as handle:
        try:
            status = subprocess.run(argv, env=env, stdout=handle, cwd=cwd,
                                    stderr=subprocess.STDOUT,
                                    timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            # keep the measurement: the profiles written so far still count,
            # and the overrun is reported as a driver failure
            handle.write('\nTIMEOUT after %d s\n' % timeout)
            status = 124
    for n, stray in enumerate(sorted(cwd.rglob('*.profraw'))):
        stray.rename(profiles / ('%s-cwd-%d.profraw' % (name, n)))
    profile_errors = 'LLVM Profile Error' in log.read_text(errors='replace')
    return status, profile_errors


def merge(name, profile_dirs):
    raw = sorted(p for d in profile_dirs for p in d.glob('*.profraw'))
    listing = out / (name + '-profiles.txt')
    listing.write_text(''.join(str(p) + '\n' for p in raw))
    merged = out / (name + '.profdata')
    log = out / (name + '-merge.log')
    with log.open('w') as handle:
        status = subprocess.run(['llvm-profdata', 'merge', '-sparse', '-f',
                                 str(listing), '-o', str(merged)],
                                stdout=handle, stderr=subprocess.STDOUT).returncode
    return {'profiles': len(raw), 'merge_status': status,
            'merge_log_bytes': log.stat().st_size, 'profdata': str(merged)}


def llvm_export(name, objects, profdata, summary_only=False):
    target = out / (name + '.json')
    log = out / (name + '.log')
    command = ['llvm-cov', 'export', str(objects[0])]
    for extra in objects[1:]:
        command += ['-object', str(extra)]
    command.append('--empty-profile' if profdata is None
                   else '-instr-profile=' + str(profdata))
    if summary_only:
        command.append('-summary-only')
    with target.open('w') as handle, log.open('w') as err:
        status = subprocess.run(command, stdout=handle, stderr=err).returncode
    text = log.read_text(errors='replace')
    return target, {'status': status, 'log': str(log), 'command': command,
                    'warnings': [line for line in text.splitlines() if line.strip()]}


def file_summaries(export_path):
    data = json.loads(export_path.read_text())['data'][0]
    rows = {}
    for entry in data['files']:
        path = str(Path(entry['filename']).resolve())
        if path in source_hashes:
            rows[path] = entry['summary']
    functions = {}
    for fn in data.get('functions', []):
        path = str(Path(fn['filenames'][0]).resolve())
        if path in source_hashes:
            functions.setdefault(path, {}).setdefault(
                fn['regions'][0][0] if fn['regions'] else 0, []).append(
                (fn['name'], fn['count']))
    return rows, functions


def measured_rows(objects, profdata, label):
    """Measured export audited against an empty-profile export of the same
    objects; returns per-file rows with authoritative denominators."""
    measured, info = llvm_export('export-' + label, objects, profdata)
    baseline, base_info = llvm_export('export-' + label + '-empty', objects, None,
                                      summary_only=True)
    m_rows, functions = file_summaries(measured)
    b_rows, _ = file_summaries(baseline)
    rows = {}
    for path in source_hashes:
        if path not in b_rows and path not in m_rows:
            rows[path] = {'mapped': False,
                          'physical_lines': sum(1 for _ in open(path, 'rb'))}
            continue
        m = m_rows.get(path)
        b = b_rows.get(path, m)
        row = {'mapped': True, 'denominator_audit': {}}
        for key in ('lines', 'branches', 'functions', 'regions'):
            covered = m[key]['covered'] if m else 0
            count_m = m[key]['count'] if m else 0
            count_b = b[key]['count']
            # The empty profile can lack branch regions that only emitted
            # copies carry; the authoritative count is the larger mapping.
            count = max(count_m, count_b)
            row[key] = [covered, count]
            if count_b > count_m:
                row['denominator_audit'][key] = {'measured': count_m,
                                                 'empty_profile': count_b}
        unexecuted = []
        for line, entries in sorted(functions.get(path, {}).items()):
            if all(count == 0 for _, count in entries):
                unexecuted.append({'line': line, 'names': sorted({n for n, _ in entries})})
        row['unexecuted_functions'] = unexecuted
        rows[path] = row
    return rows, {'measured': info, 'empty_profile': base_info}


# ---- trace-continuity waiver (HT-C markers) -------------------------------
# Production sources mark disabled trace-continuity code with comment-only
# markers: a region ("HT-C BEGIN: trace continuity across ...", whole
# functions) or a block ("HT-C BEGIN: disabled trace continuity.", the body of
# a branch inside a live function), each closed by "HT-C END". The "live"
# configuration reports coverage without them: functions starting inside a
# region are excluded through llvm-cov's -name-allowlist (exact llvm-cov
# accounting), and lines/branch outcomes inside blocks are subtracted from
# their live functions using the per-line view of the same data.
def htc_spans(path):
    spans, begin, kind = [], None, None
    lines = Path(path).read_text(errors='replace').splitlines()
    i = 0
    while i < len(lines):
        text = lines[i].strip()
        if 'HT-C BEGIN' in text:
            kind = 'region' if 'trace continuity across' in text else 'block'
            while not lines[i].rstrip().endswith('*/'):
                i += 1
            begin = i + 2
        elif text == '/* HT-C END */':
            spans.append((begin, i, kind))
            begin = None
        i += 1
    return spans


def live_rows(objects, profdata, label, measured_export, base_rows):
    """Live rows: the measured file rows minus HT-C regions and blocks.

    Region exclusion is exact llvm-cov accounting: `llvm-cov report
    -show-functions` gives every function's own line/branch summary, and a
    file's summary merges the functions that share a source location
    (instantiation groups: counts from one member, coverage the maximum), so
    each excluded group subtracts that merged summary. Block exclusion
    subtracts the lines (merged per-line view of `llvm-cov show`) and branch
    outcomes (export branch records, merged by location) inside the block,
    for the live functions only."""
    data = json.loads(Path(measured_export).read_text())['data'][0]
    span_map = {p: htc_spans(p) for p in source_hashes
                if p.startswith(str(daemon_dir) + '/')}
    location, executed = {}, {}
    for fn in data.get('functions', []):
        path = str(Path(fn['filenames'][0]).resolve())
        if not fn['regions']:
            continue
        location[fn['name']] = (path, fn['regions'][0][0], fn['regions'][0][1])
        executed[fn['name']] = executed.get(fn['name'], 0) + fn['count']
    objargs = [str(objects[0])] + sum([['-object', str(o)] for o in objects[1:]], [])
    rows, blocks_total, excluded_total = {}, {'lines': [0, 0], 'branches': [0, 0]}, 0
    for path, row in base_rows.items():
        if not path.startswith(str(daemon_dir) + '/'):
            continue
        spans = span_map.get(path, [])
        if not row.get('mapped') or not spans:
            rows[path] = row
            continue
        new = {'mapped': True, 'lines': list(row['lines']),
               'branches': list(row['branches']), 'functions': list(row['functions'])}
        regions = [(a, b) for a, b, k in spans if k == 'region']
        blocks = [(a, b) for a, b, k in spans if k == 'block']
        report = subprocess.run(['llvm-cov', 'report'] + objargs +
                                ['-instr-profile=' + str(profdata), '-show-functions',
                                 path], capture_output=True, text=True).stdout
        groups = {}
        for line in report.splitlines():
            fields = line.split()
            if len(fields) != 10 or fields[0] not in location:
                continue
            fpath, fline, fcol = location[fields[0]]
            if fpath != path or not any(a <= fline <= b for a, b in regions):
                continue
            lines_n, lines_miss = int(fields[4]), int(fields[5])
            br_n, br_miss = int(fields[7]), int(fields[8])
            g = groups.setdefault((fline, fcol), {'lines': [0, 0], 'branches': [0, 0],
                                                  'executed': False})
            g['lines'] = [max(g['lines'][0], lines_n - lines_miss), max(g['lines'][1], lines_n)]
            g['branches'] = [max(g['branches'][0], br_n - br_miss),
                             max(g['branches'][1], br_n)]
            g['executed'] |= executed.get(fields[0], 0) > 0
        for g in groups.values():
            for key in ('lines', 'branches'):
                new[key][0] -= g[key][0]
                new[key][1] -= g[key][1]
            new['functions'][0] -= 1 if g['executed'] else 0
            new['functions'][1] -= 1
        excluded_total += len(groups)
        if blocks:
            show = subprocess.run(['llvm-cov', 'show'] + objargs +
                                  ['-instr-profile=' + str(profdata),
                                   '-show-line-counts', '-use-color=false', path],
                                  capture_output=True, text=True).stdout
            seen, exe, cov = set(), 0, 0
            for line in show.splitlines():
                mm = re.match(r'\s*(\d+)\|\s*([0-9.kMGE+]*)\|', line)
                if not mm:
                    continue
                n = int(mm.group(1))
                if n in seen:
                    continue
                seen.add(n)
                if mm.group(2) and any(a <= n <= b for a, b in blocks):
                    exe += 1
                    cov += mm.group(2) != '0'
            outcomes = {}
            for fn in data.get('functions', []):
                if str(Path(fn['filenames'][0]).resolve()) != path:
                    continue
                for br in fn.get('branches', []):
                    if br[6] != 0 or not any(a <= br[0] <= b for a, b in blocks):
                        continue
                    key = (br[0], br[1], br[2], br[3])
                    t, f = outcomes.get(key, (0, 0))
                    outcomes[key] = (max(t, br[4]), max(f, br[5]))
            bcount = 2 * len(outcomes)
            bcov = sum((t > 0) + (f > 0) for t, f in outcomes.values())
            new['lines'] = [new['lines'][0] - cov, new['lines'][1] - exe]
            new['branches'] = [new['branches'][0] - bcov, new['branches'][1] - bcount]
            new['htc_blocks'] = {'lines': [cov, exe], 'branches': [bcov, bcount]}
            for key, (c, n) in (('lines', (cov, exe)), ('branches', (bcov, bcount))):
                blocks_total[key][0] += c
                blocks_total[key][1] += n
        new['htc_excluded_groups'] = len(groups)
        rows[path] = new
    return rows, {'excluded_function_groups': excluded_total,
                  'blocks_subtracted': blocks_total,
                  'spans': {p: v for p, v in span_map.items() if v}}

def totals(rows, predicate):
    acc = {'lines': [0, 0], 'branches': [0, 0], 'functions': [0, 0]}
    unmapped = []
    for path, row in rows.items():
        if not predicate(path):
            continue
        if not row['mapped']:
            unmapped.append(path)
            continue
        for key in acc:
            acc[key][0] += row[key][0]
            acc[key][1] += row[key][1]
    result = {key: {'covered': c, 'count': n,
                    'percent': round(100.0 * c / n, 4) if n else None}
              for key, (c, n) in acc.items()}
    result['unmapped_files'] = unmapped
    return result


def pct(pair):
    return f'{pair[0]}/{pair[1]} ({100.0 * pair[0] / pair[1]:.2f}%)' if pair[1] else '0/0'


def header_object(directory, defines):
    directory.mkdir()
    tu = directory / 'header-denominator.cc'
    tu.write_text(''.join('#include "%s"\n' % p.name for p in headers))
    obj = directory / 'header-denominator.o'
    r = subprocess.run(['/usr/bin/c++', *FLAGS, '-std=c++17', '-femit-all-decls',
                        *defines, '-I' + str(daemon_dir), '-I' + str(root / 'sys'),
                        '-I' + str(root / 'sys/dev/dttransport'), '-c', str(tu),
                        '-o', str(obj)], capture_output=True, text=True)
    (directory / 'build.log').write_text(r.stdout + r.stderr)
    if r.returncode:
        raise SystemExit('header denominator object failed to build')
    return obj


summary = {'collections': {}, 'provenance': provenance}
failed = False

if 'daemon' in collections:
    profiles = out / 'daemon-profiles'
    statuses = {}
    profile_errors = {}
    if not args.skip_native:
        path = tests / 'native-daemon.py'
        provenance['drivers']['native-daemon'] = sha(path)
        statuses['native-daemon'], profile_errors['native-daemon'] = run_driver(
            'native-daemon', [sys.executable, str(path), str(out / 'native-daemon')],
            profiles)
    path = tests / 'daemon-extra.py'
    provenance['drivers']['daemon-extra'] = sha(path)
    objects_arg = str(out / 'native-daemon') if not args.skip_native else '-'
    statuses['daemon-extra'], profile_errors['daemon-extra'] = run_driver(
        'daemon-extra', [sys.executable, str(path), str(out / 'daemon-extra'),
                         objects_arg, *args.extra_suite], profiles,
        timeout=12 * 3600)  # includes the live-sweep incarnation sweeps
    # Existing property/fuzz suites whose subjects are daemon headers
    # (transfer, rebind, protocol and configuration helpers). Their binaries
    # join the export so header copies they execute are credited; other
    # sources they compile (libdtrace list, bhyve descriptors) are filtered
    # out of the daemon rows by path.
    related = ('transfer-properties', 'rebind-properties', 'protocol-fuzz',
               'discovery-helpers')
    for name in related:
        path = tests / (name + '.py')
        provenance['drivers'][name] = sha(path)
        statuses[name], profile_errors[name] = run_driver(
            name, [sys.executable, str(path), str(out / name)], profiles)
    hdr = header_object(out / 'header-denominator', [])
    # Production-configuration mapping binary (never executed).
    prod = out / 'production-build'
    prod.mkdir()
    prod_flags = ['/usr/bin/c++', *FLAGS, '-std=c++17', '-O0', '-g',
                  '-Wno-c11-extensions', '-Wno-gcc-compat',
                  '-Wno-gnu-anonymous-struct', '-Wno-zero-length-array',
                  '-Wno-c99-designator', '-I' + str(root / 'sys/dev/dttransport'),
                  '-I' + str(root / 'sys'), '-I' + str(daemon_dir)]
    makefile = (daemon_dir / 'Makefile').read_text()
    prod_srcs = re.search(r'SRCS=\s*(.*?)\n\n', makefile, re.S).group(1)
    prod_srcs = [s for s in re.split(r'[\s\\]+', prod_srcs) if s]
    unlisted = sorted(p.name for p in daemon_dir.glob('*.cc') if p.name not in prod_srcs)

    def build_prod(src):
        obj = prod / (Path(src).stem + '.o')
        r = subprocess.run(prod_flags + ['-c', str(daemon_dir / src), '-o', str(obj)],
                           capture_output=True, text=True)
        (prod / (Path(src).stem + '-build.log')).write_text(r.stdout + r.stderr)
        return r.returncode, obj
    with concurrent.futures.ThreadPoolExecutor(max_workers=ncpu) as pool:
        built = list(pool.map(build_prod, prod_srcs))
    prod_status = max(code for code, _ in built)
    prod_bin = prod / 'dtraced-production-mapping'
    if prod_status == 0:
        compat = prod / 'compat.o'
        subprocess.run(prod_flags + ['-c', str(tests / 'native-daemon-compat.cc'),
                                     '-o', str(compat)], check=True)
        prod_status = subprocess.run(prod_flags + [str(o) for _, o in built] +
                                     [str(compat), '-pthread', '-lcrypto', '-lutil',
                                      '-o', str(prod_bin)]).returncode
    merged = merge('daemon', [profiles])
    native_bin = out / 'daemon-extra' / 'dtraced-mapping'
    def is_elf(p):
        with open(p, 'rb') as f:
            return f.read(4) == b'\x7fELF'
    suite_dirs = [out / 'native-daemon', out / 'daemon-extra'] + \
        [out / name for name in related]
    suite_bins = sorted(p for d in suite_dirs if d.exists() for p in d.iterdir()
                        if p.is_file() and p != native_bin and
                        ((os.access(p, os.X_OK) and p.suffix == '') or
                         p.suffix == '.so') and is_elf(p))
    collection = {'driver_status': statuses, 'profile_errors': profile_errors,
                  'merge': merged, 'production_build_status': prod_status,
                  'production_srcs': prod_srcs, 'cc_not_in_makefile': unlisted,
                  'suite_binaries': [str(p) for p in suite_bins], 'configurations': {}}
    failed |= any(statuses.values()) or any(profile_errors.values()) or \
        merged['merge_status'] != 0 or merged['merge_log_bytes'] != 0 or prod_status != 0
    if merged['merge_status'] == 0:
        native_rows, info = measured_rows([native_bin, *suite_bins, hdr],
                                          merged['profdata'], 'native-test')
        info['binary_sha256'] = sha(native_bin)
        is_daemon = lambda p: p.startswith(str(daemon_dir) + '/')
        info['files'] = {p: r for p, r in native_rows.items() if is_daemon(p)}
        info['component'] = totals(native_rows, is_daemon)
        collection['configurations']['native-test'] = info
        lrows, linfo = live_rows([native_bin, *suite_bins, hdr], merged['profdata'],
                                 'native-test', out / 'export-native-test.json',
                                 native_rows)
        linfo['files'] = lrows
        linfo['component'] = totals(lrows, lambda p: True)
        linfo['measured'] = {'warnings': []}
        linfo['note'] = ('live daemon code: HT-C trace-continuity regions and '
                         'blocks excluded (comment markers in the sources)')
        collection['configurations']['live'] = linfo
        if prod_status == 0:
            prod_rows, pinfo = measured_rows([prod_bin, hdr], merged['profdata'],
                                             'production')
            pinfo['binary_sha256'] = sha(prod_bin)
            # Only sources that test DTRACED_NATIVE_TEST compile differently;
            # every other file has identical function hashes in both builds,
            # so its native-test union row (including suites that include an
            # unmodified production .cc) is also its production row.
            dependent = sorted(p for p in native_rows if is_daemon(p) and
                               'DTRACED_NATIVE_TEST' in Path(p).read_text())
            combined = {}
            for p in native_rows:
                if not is_daemon(p):
                    continue
                combined[p] = prod_rows[p] if p in dependent else native_rows[p]
            pinfo['files'] = combined
            pinfo['configuration_dependent_files'] = dependent
            pinfo['component'] = totals(combined, lambda p: True)
            pinfo['production_objects_only'] = totals(
                {p: r for p, r in prod_rows.items() if is_daemon(p)}, lambda p: True)
            pinfo['note'] = ('rows for files containing DTRACED_NATIVE_TEST come from '
                             'production-configuration objects only; other rows are '
                             'configuration independent')
            collection['configurations']['production'] = pinfo
    summary['collections']['daemon'] = collection

if 'ctl' in collections:
    obj = out / 'ctl-obj'
    env = os.environ.copy()
    env.pop('CXXFLAGS', None)
    env.update(PATH=str(wrappers) + ':/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
               MAKEOBJDIRPREFIX=str(obj))
    build_log = out / 'ctl-build.log'
    with build_log.open('w') as handle:
        build_status = subprocess.run(
            ['make', '-j' + str(ncpu), '-C', str(ctl_dir), '-m',
             str(root / 'share/mk'), 'SRCTOP=' + str(root), 'SRCCONF=/dev/null',
             '__MAKE_CONF=/dev/null', 'all'],
            env=env, stdout=handle, stderr=subprocess.STDOUT).returncode
    binaries = sorted(obj.rglob('usr.sbin/dtracedctl/dtracedctl'))
    collection = {'build_status': build_status, 'configurations': {}}
    failed |= build_status != 0 or not binaries
    if build_status == 0 and binaries:
        binary = binaries[0]
        profiles = out / 'ctl-profiles'
        driver = tests / 'control-cli-offline.py'
        provenance['drivers']['control-cli-offline'] = sha(driver)
        status, perr = run_driver('control-cli-offline',
                                  [sys.executable, str(driver), str(out / 'ctl-run'),
                                   str(binary)], profiles)
        extra = tests / 'control-cli-extra.py'
        provenance['drivers']['control-cli-extra'] = sha(extra)
        extra_status, extra_perr = run_driver(
            'control-cli-extra', [sys.executable, str(extra), str(out / 'ctl-extra'),
                                  str(binary)], profiles)
        collection['driver_status'] = {'control-cli-offline': status,
                                       'control-cli-extra': extra_status}
        collection['profile_errors'] = perr or extra_perr
        status = status or extra_status
        perr = perr or extra_perr
        merged = merge('ctl', [profiles])
        collection['merge'] = merged
        failed |= bool(status) or perr or merged['merge_status'] != 0 or \
            merged['merge_log_bytes'] != 0
        if merged['merge_status'] == 0:
            rows, info = measured_rows([binary], merged['profdata'], 'dtracedctl')
            info['binary_sha256'] = sha(binary)
            info['files'] = {p: r for p, r in rows.items() if r['mapped']}
            info['component'] = totals(rows, lambda p: p.startswith(str(ctl_dir) + '/'))
            info['shared_headers_as_mapped_in_dtracedctl'] = totals(
                info['files'], lambda p: p.startswith(str(daemon_dir) + '/'))
            collection['configurations']['dtracedctl'] = info
    summary['collections']['ctl'] = collection

after = {str(p): sha(p) for p in production_sources()}
summary['source_hashes_stable'] = after == source_hashes
summary['source_sha256'] = source_hashes
failed |= not summary['source_hashes_stable']
summary['passed'] = not failed
(out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')

for name, collection in summary['collections'].items():
    for label, info in collection.get('configurations', {}).items():
        comp = info['component']
        print(f"{name}/{label}: lines {comp['lines']['covered']}/{comp['lines']['count']} "
              f"({comp['lines']['percent']}%) branches {comp['branches']['covered']}/"
              f"{comp['branches']['count']} ({comp['branches']['percent']}%) functions "
              f"{comp['functions']['covered']}/{comp['functions']['count']} "
              f"({comp['functions']['percent']}%) unmapped={len(comp['unmapped_files'])} "
              f"export_warnings={info['measured']['warnings']}")
        for path, row in sorted(info['files'].items()):
            if row['mapped'] and row['lines'][1]:
                audit = ' AUDIT' if row.get('denominator_audit') else ''
                print(f"  {Path(path).name:36} L {pct(row['lines']):24} "
                      f"B {pct(row['branches']):24} F {pct(row['functions'])}{audit}")
            elif not row['mapped']:
                print(f"  {Path(path).name:36} UNMAPPED ({row['physical_lines']} physical lines;"
                      " no executable mapping even with -femit-all-decls)")
print('PASS' if not failed else 'FAIL', '- evidence:', out,
      '(exploratory)' if exploratory else '')
raise SystemExit(1 if failed else 0)
