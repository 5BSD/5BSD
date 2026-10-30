#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Declared Bazel targets for the OTel components, compared with independent Make builds.

Builds the OpenTelemetry components listed in targets/sources.json (the
lib/libotelexport and cddl/lib/libdtotel INTERNALLIB archives, hwstat,
bsdinstruments, otelconf, otelpfd, otelauditd and their test programs) with
the declared staged toolchain, and the same components through maintained
Make buildenv against the same staged SDK.  Not a system build backend;
build-bsd selects Make.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bsd_toolchain  # noqa: E402

MARKER = 'OTEL_BAZEL_DEPENDENCY_PROBE'
LINK_MARKER = 'OTEL_BAZEL_LINK_PROBE'
ABI_FAILURE = re.compile(r'Undefined symbol|version \S+ required by|Shared object "[^"]+" not found')

# Bazel-only compile tokens removed before comparing with Make, and why.
EXPLAINED_BAZEL_TOKENS = {
    '-frandom-seed': 'Bazel seeds per-output randomness with the output path; it affects only '
                     'compiler-generated unique names, not C code generation (checked by '
                     'object/section comparison).',
    '-iquote': 'Bazel workspace quote-include roots (".", bazel-out/<cfg>/bin, external/bazel_tools); '
               'Make relies on the including file\'s directory, which clang searches first in both.',
    '-isystem bazel-out': 'generated-file twin of each declared include directory; empty for the OTel '
                          'targets; for libdtrace it holds dt_grammar.h, where Make has -I${.OBJDIR} '
                          '(recorded as outside the source tree and also left out of the comparison).',
    '-nostdinc/-isystem SDK': 'explicit staged clang resource and sysroot include directories; '
                              'Make reaches the same directories through --sysroot defaults.',
    '-I vs -isystem': 'Bazel `includes` produces -isystem; with Make policy -Wsystem-headers the '
                      'diagnostics are unchanged and the search order is preserved and verified.',
    '-fdebug-compilation-dir=.': 'toolchain feature: Bazel sandboxes each action in a numbered '
                                 'directory that would otherwise be recorded as DW_AT_comp_dir, making '
                                 'debug output differ between identical rebuilds. Make records its '
                                 'absolute object directory instead. Debug sections only.',
    '-MD/-MF': 'dependency-file names differ (Make .depend.*, Bazel .d); Bazel also verifies '
               'inclusions against declared inputs.',
}


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def object_path(value, label):
    if not value.is_absolute() or any(c in str(value) for c in '\n\r\x00$'):
        raise ValueError(label + ' must be absolute without newline, NUL or $')
    return value


class Recorder:
    def __init__(self, path):
        self.path = path
        self.records = []

    def run(self, argv, expect_success=True, cwd=None, env=None, timeout=None, check=True):
        argv = [str(x) for x in argv]
        try:
            result = subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, timeout=timeout)
            status, out, err = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            status, out, err = 'timeout', error.stdout or '', error.stderr or ''
            out = out if isinstance(out, str) else out.decode(errors='replace')
            err = err if isinstance(err, str) else err.decode(errors='replace')
        self.records.append({'argv': argv, 'cwd': str(cwd) if cwd else None,
                             'exit_code': status, 'stdout': out, 'stderr': err})
        self.path.write_text(json.dumps(self.records, indent=2) + '\n')
        if check and (status == 0) != expect_success:
            raise RuntimeError('unexpected command result (%s): %s\n%s%s' %
                               (status, shlex.join(argv), out[-4000:], err[-4000:]))
        return status, out, err


def path_string_check(objcopy, make_object, bazel_object, src, scratch, ms, bs, differing):
    """Explain object differences confined to string data and its users.

    Make passes absolute source paths, Bazel workspace-relative ones, and
    __FILE__ (assert(), ATF macros) embeds them.  'explained' is true when
    every differing merged-string section holds the same strings once the
    source-root prefix is removed, and every other differing non-debug
    section (relocations, .symtab) keeps its size, i.e. only offsets moved.
    """
    import subprocess
    report = {'string_sections_equal_after_prefix': {}, 'other_sections_same_size': {}}
    explained = True
    prefix = (str(src) + '/').encode()
    for name in differing:
        if name.startswith('.debug_'):
            continue
        if name.startswith('.rodata.str'):
            texts = []
            for obj in (make_object, bazel_object):
                dump = scratch / 'strings.bin'
                subprocess.run([str(objcopy), '--dump-section=%s=%s' % (name, dump), str(obj),
                                str(scratch / 'discard')], check=True,
                               env={'PATH': '/bin:/usr/bin', 'LC_ALL': 'C'})
                texts.append(dump.read_bytes())
                dump.unlink()
                (scratch / 'discard').unlink()
            same = (sorted(x.replace(prefix, b'') for x in texts[0].split(b'\0')) ==
                    sorted(texts[1].split(b'\0')))
            report['string_sections_equal_after_prefix'][name] = same
            explained &= same
        else:
            same = name in ms and name in bs and ms[name]['size'] == bs[name]['size']
            report['other_sections_same_size'][name] = same
            explained &= same
    report['explained'] = explained
    return report


def make_compile_command(dry_run, obj, by_basename=False):
    matches = []
    for line in dry_run.splitlines():
        tokens = shlex.split(line) if ' -c ' in line else []
        if '-o' not in tokens:
            continue
        target = tokens[tokens.index('-o') + 1]
        # Generated sources keep their protogen/<set>/... subdirectory in the
        # Make object name (bsd.obj.mk); Bazel names objects by basename.
        if target == obj or (by_basename and Path(target).name == obj):
            matches.append(tokens)
    # bsd.progs.mk runs one sub-make per program, so an object shared by
    # several programs of a directory appears once per program; it is the
    # same file and must be compiled the same way each time.
    # Only the dependency-file options (-MD -MF -MT) may differ.
    def key(tokens):
        return tuple(t for t in tokens if not (t == '-MD' or t.startswith('-MF') or
                                               t.startswith('-MT')))
    if len({key(m) for m in matches}) != 1:
        raise ValueError('expected one Make compile command for ' + obj)
    return matches[0]


def make_link_command(dry_run, output):
    matches = [shlex.split(line) for line in dry_run.splitlines()
               if ' -o ' + output + ' ' in line and ' -c ' not in line]
    if len(matches) != 1:
        raise ValueError('expected one Make link command for ' + output)
    return matches[0]


def normalize_make_compile(tokens, src):
    flags, includes, i = [], [], 1
    while i < len(tokens):
        t = tokens[i]
        if t in ('-target', '-o', '-c'):
            i += 2
            continue
        if t == '-include':
            # Forced include: compare the workspace-relative header path.
            flags += [t, os.path.relpath(os.path.normpath(tokens[i + 1]), src)]
            i += 2
            continue
        if t.startswith('-I'):
            includes.append(os.path.normpath(t[2:]))
        elif not (t.startswith('--sysroot=') or t.startswith('-B') or t == '-MD' or
                  t.startswith('-MF') or t.startswith('-MT')):
            flags.append(t)
        i += 1
    relative, missing = [], []
    for path in includes:
        rel = os.path.relpath(path, src)
        if rel.startswith('..'):
            # -I${.OBJDIR}: Make's generated headers; Bazel reaches its
            # generated files through the bazel-out twin of an `includes`
            # directory, which normalize_bazel_compile drops.
            missing.append(path)
        elif not (src / rel).is_dir():
            missing.append(rel)
        elif rel not in relative:
            relative.append(rel)
    return flags, relative, missing


def normalize_bazel_compile(tokens):
    flags, includes, dropped, i = [], [], [], 1
    while i < len(tokens):
        t = tokens[i]
        if t in ('-MF', '-iquote', '-c', '-o'):
            if t == '-iquote':
                dropped.append(t + ' ' + tokens[i + 1])
            i += 2
            continue
        if t == '-isystem':
            path = tokens[i + 1]
            if path.startswith('bazel-out/') or path.startswith('toolchain/'):
                dropped.append(t + ' ' + path)
            else:
                includes.append(path)
            i += 2
            continue
        if t == '-I':
            includes.append(tokens[i + 1])
            i += 2
            continue
        if t.startswith('-I'):
            # copts -I: a component's own include directory that Make adds
            # for its objects only (not propagated to dependents).
            includes.append(t[2:])
        elif t.startswith('-frandom-seed=') or t in ('-MD', '-nostdinc', '-fdebug-compilation-dir=.'):
            dropped.append(t)
        elif not (t.startswith('--target=') or t.startswith('--sysroot=')):
            flags.append(t)
        i += 1
    return flags, includes, dropped


def link_summary(tokens, archive_dirs=()):
    options, libraries, objects = set(), [], []
    for t in tokens:
        if t.startswith('-Wl,'):
            options.update('-Wl,' + x for x in t[4:].split(','))
        elif t in ('-pie', '-gz=zlib', '-static', '-shared'):
            options.add(t)
        elif t.startswith('-l'):
            libraries.append(t)
        elif t.endswith('.a'):
            libraries.append('-l' + Path(t).name[3:-2])
        elif t.endswith('.o') or t.endswith('.pieo'):
            objects.append(re.sub(r'(\.pic)?\.o$|\.pieo$', '', Path(t).name))
    ordered = list(dict.fromkeys(libraries))
    return {'options': sorted(options), 'libraries_order': ordered,
            'libraries': sorted(ordered), 'objects': objects}


def params_file(bazel_bin, artifact):
    found = sorted(bazel_bin.glob(artifact + '-*.params'))
    if len(found) != 1:
        raise ValueError('expected one Bazel params file for ' + artifact)
    return found[0].read_text().split('\n')


def key_shape(value):
    if isinstance(value, dict):
        return {k: key_shape(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        shapes = []
        for item in value:
            shape = key_shape(item)
            if shape not in shapes:
                shapes.append(shape)
        return shapes
    return type(value).__name__


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('src', 'sysroot', 'objdump', 'awk', 'bazel', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--make', type=Path, default=Path('/usr/bin/make'))
    p.add_argument('--readelf', type=Path, default=Path('/usr/bin/readelf'))
    for name in ('target', 'cpu', 'clang-version'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--jobs', type=int, default=os.cpu_count())
    p.add_argument('--skip-host-runtime', action='store_true',
                   help='do not execute the built programs on this host')
    a = p.parse_args()
    if platform.system() != 'FreeBSD' or platform.machine() != 'amd64':
        p.error('native FreeBSD amd64 only; cross compilation is unqualified')
    if a.jobs < 1:
        p.error('--jobs must be positive')
    if not re.fullmatch(r'x86_64-unknown-freebsd[0-9]+(?:\.[0-9]+)*', a.target):
        p.error('only native amd64 FreeBSD targets are supported')
    for name in ('src', 'sysroot', 'objdump', 'awk', 'bazel', 'output', 'make', 'readelf'):
        object_path(getattr(a, name), '--' + name)
    src, sysroot = a.src.resolve(strict=True), a.sysroot.resolve(strict=True)
    bazel, make, readelf = (x.resolve(strict=True) for x in (a.bazel, a.make, a.readelf))
    objdump, awk = a.objdump.resolve(strict=True), a.awk.resolve(strict=True)
    out = a.output.resolve()
    if a.output.is_symlink() or out.exists():
        p.error('--output must be a new evidence directory')
    if out == Path('/usr/obj') or not out.is_relative_to('/usr/obj'):
        p.error('--output must be below /usr/obj')
    if out.is_relative_to(src) or src.is_relative_to(out) or out.is_relative_to(sysroot):
        p.error('--output must not overlap the source tree or staged sysroot')
    manifest_path = HERE / 'targets/sources.json'
    manifest = json.loads(manifest_path.read_text())
    clang = sysroot / 'usr/bin/clang'
    tools = {'llvm-nm': sysroot / 'usr/bin/llvm-nm', 'llvm-ar': sysroot / 'usr/bin/llvm-ar',
             'llvm-objcopy': sysroot / 'usr/bin/llvm-objcopy'}
    for path in [clang, *tools.values()]:
        if not path.is_file():
            raise ValueError('staged tool missing: ' + str(path))
    out.mkdir(parents=True)
    rec = Recorder(out / 'commands.json')
    checker = load('elf_artifact_check', 'elf-artifact-check.py')
    probe_inputs = sorted([Path(__file__).resolve(), HERE / 'bsd_toolchain.py',
                           HERE / 'cc_toolchain_config.bzl', HERE / 'bsd_component.bzl',
                           HERE / 'bsd_generate.bzl',
                           HERE / 'elf-artifact-check.py', HERE / 'elf-artifact-check-test.py',
                           manifest_path,
                           *sorted((HERE / 'targets').rglob('BUILD.bazel'))])
    result = {'scope': 'native-amd64-otel-declared-bazel-targets', 'status': 'running',
              'source_root': str(src), 'sysroot': str(sysroot), 'target': a.target,
              'jobs': a.jobs, 'production_backend': 'bsd-make',
              'probe_input_sha256': {str(x): sha(x) for x in probe_inputs},
              'tool_sha256': {str(x): sha(x) for x in (bazel, make, readelf, objdump, awk, clang,
                                                        *tools.values())},
              'system_backend_qualified': False, 'bazel9_qualified': False,
              'cross_compilation_qualified': False, 'system_runtime_qualified': False,
              'installation_package_parity': False}

    def save():
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')

    # Source inputs are hashed before the Make reference is built and
    # rechecked at the end: an edit between the two builds would make the
    # comparison meaningless (found when a test source changed mid-run).
    source_files = sorted({f for c in manifest['components'] for f in (src / c['path']).rglob('*')
                           if f.is_file()} |
                          {f for t in manifest.get('source_trees', []) for f in (src / t).rglob('*')
                           if f.is_file() and 'tests' not in f.relative_to(src / t).parts} |
                          {f for t in manifest['header_trees'] for f in (src / t).rglob('*.h')})
    source_digest = {str(f): sha(f) for f in source_files}
    try:
        # ---- Independent Make references through maintained buildenv. ----
        make_env = {'PATH': '/bin:/usr/bin:/usr/local/bin', 'HOME': os.environ.get('HOME', '/nonexistent'),
                    'LC_ALL': 'C', 'MAKEOBJDIRPREFIX': str(out / 'make/objprefix'),
                    'SRCCONF': '/dev/null', '__MAKE_CONF': '/dev/null'}
        (out / 'make/objprefix').mkdir(parents=True)

        def buildenv(command, **kw):
            return rec.run([make, '-C', src, 'buildenv', 'WORLDTMP=' + str(sysroot),
                            'BUILDENV_SHELL=' + shlex.join([str(x) for x in command])],
                           env=make_env, **kw)

        _, env_out, _ = buildenv(['/usr/bin/env'])
        env_lines = env_out.splitlines()
        if (env_lines[0] != 'Entering world for amd64:amd64' or
                'SYSROOT=' + str(sysroot) not in env_lines or
                not any(x.startswith('CC=') and '--sysroot=' + str(sysroot) in x and
                        '-target ' + a.target in x for x in env_lines)):
            raise ValueError('Make buildenv does not use the explicit staged sysroot/target')
        private_libs = {x['component']: x for x in manifest['private_libraries']}
        library_dir = out / 'make/libotelexport'
        make_info = {}
        for component in manifest['components']:
            objdir = out / 'make' / component['name']
            objdir.mkdir(exist_ok=True)
            # src.libnames.mk insists LIB<NAME>DIR is .OBJDIR inside the library itself;
            # every consumer uses the private library builds made before it.
            common_vars = [lib['make_var'] + '=' + str(out / 'make' / name)
                           for name, lib in private_libs.items() if name != component['name']]
            base = ['/usr/bin/env', 'MAKEOBJDIR=' + str(objdir), make, '-C', src / component['path']]
            # bsd.progs.mk (ATF_TESTS_C, PROGS) keeps per-program sources in SRCS.<prog>.
            srcs_vars = [x['srcs_var'] for x in component['artifacts']]
            query = ['-V', 'CFLAGS', '-V', 'LDFLAGS', '-V', 'WARNS']
            for var in srcs_vars:
                query += ['-V', var]
            _, values, _ = buildenv(base + query + common_vars)
            values = values.splitlines()[1:]
            artifact_srcs = {}
            for item, value in zip(component['artifacts'], values[3:]):
                listed = value.split() or ([item['default_src']] if 'default_src' in item else [])
                if not listed:
                    raise ValueError('no Make sources for ' + item['label'])
                artifact_srcs[item['label']] = listed
            _, dry, _ = buildenv(base + ['-n'] + component['make_targets'] + common_vars)
            (out / 'make' / (component['name'] + '.dry-run.txt')).write_text(dry)
            buildenv(base + ['-j' + str(a.jobs)] + component['make_targets'] + common_vars)
            make_info[component['name']] = {'objdir': str(objdir), 'srcs': artifact_srcs,
                                            'cflags': values[0], 'ldflags': values[1],
                                            'warns': values[2], 'dry_run': dry}
        result['make_reference'] = {k: {x: y for x, y in v.items() if x != 'dry_run'}
                                    for k, v in make_info.items()}
        result['make_configuration'] = {k: make_env[k] for k in ('SRCCONF', '__MAKE_CONF', 'MAKEOBJDIRPREFIX')}

        # ---- Declared Bazel workspace. ----
        ws = out / 'workspace'
        ws.mkdir()
        bsd_toolchain.stage_toolchain(ws / 'toolchain', sysroot, objdump, awk,
                                      a.target, a.cpu, a.clang_version)
        for component in manifest['components']:
            shutil.copytree(src / component['path'], ws / component['path'],
                            symlinks=False, dirs_exist_ok=True)
        for tree in manifest.get('source_trees', []):
            shutil.copytree(src / tree, ws / tree, symlinks=False, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns('tests'))
        for tree in manifest['header_trees']:
            for header in sorted((src / tree).rglob('*.h')):
                if not header.resolve(strict=True).is_relative_to(src):
                    raise ValueError('header escapes source tree: ' + str(header))
                destination = ws / header.relative_to(src)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(header, destination)
        for name in ('BUILD', 'BUILD.bazel', 'WORKSPACE', 'WORKSPACE.bazel', 'MODULE.bazel'):
            stray = [x for x in ws.rglob(name) if not x.is_relative_to(ws / 'toolchain')]
            if stray:
                raise ValueError('source tree supplied its own Bazel file: ' + str(stray[0]))
        overlay = HERE / 'targets'
        for build_file in sorted(overlay.rglob('BUILD.bazel')):
            destination = ws / build_file.relative_to(overlay)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(build_file, destination)
        (ws / 'WORKSPACE').write_text('workspace(name="bsd_otel_pilot")\n')
        snapshot = {str(f.relative_to(ws)): sha(f) for f in sorted(ws.rglob('*')) if f.is_file()}
        (out / 'inputs.json').write_text(json.dumps(snapshot, indent=2) + '\n')
        result['inputs_sha256'] = sha(out / 'inputs.json')

        prefix = [bazel, '--batch', '--output_user_root=' + str(out / 'cache'), '--ignore_all_rc_files']
        flags = bsd_toolchain.build_flags(a.cpu, a.jobs) + ['--compilation_mode=opt', '--strip=never']
        artifacts = [dict(x, component=c['name']) for c in manifest['components'] for x in c['artifacts']]
        labels = [x['label'] for x in artifacts]
        build = prefix + ['build'] + flags + labels
        result['bazel_version'] = rec.run(prefix + ['version'], cwd=ws)[1]
        rec.run(build, cwd=ws)
        bazel_bin = ws / 'bazel-bin'
        outputs = {x['bazel']: sha(bazel_bin / x['bazel']) for x in artifacts}
        result['bazel_outputs'] = outputs

        # ---- Source lists in BUILD files must equal Make SRCS. ----
        def srcs_check():
            report = {}
            for item in artifacts:
                _, listed, _ = rec.run(prefix + ['query', 'labels(srcs, %s)' % item['label']], cwd=ws)
                bazel_srcs = [x.rsplit(':', 1)[1] for x in listed.split() if x.endswith('.c')]
                # Generated sources (protoc-gen.mk protogen/<set>/...) come
                # from a rule target; protobuf-probe.py compares them.
                make_srcs = [x for x in make_info[item['component']]['srcs'][item['label']]
                             if x.endswith('.c') and not x.startswith('protogen/')]
                if sorted(bazel_srcs) != sorted(make_srcs):
                    raise ValueError('BUILD srcs differ from Make SRCS for ' + item['label'])
                # Query output is sorted; source order is checked through archive
                # member order and link object order below.
                report[item['label']] = {'bazel': sorted(bazel_srcs), 'make': make_srcs}
            return report

        result['srcs_match_make'] = srcs_check()
        build_file = ws / 'lib/libotelexport/BUILD.bazel'
        original_build = build_file.read_text()
        try:
            if original_build.count('"oe_text.c",') != 1:
                raise RuntimeError('drift-guard fixture expects one oe_text.c entry')
            build_file.write_text(original_build.replace('"oe_text.c",', '', 1))
            try:
                srcs_check()
            except ValueError as error:
                result['srcs_drift_rejected'] = str(error)
            else:
                raise RuntimeError('removed BUILD source was not detected')
        finally:
            build_file.write_text(original_build)

        # ---- Compile flags against Make commands. ----
        _, aquery, _ = rec.run(prefix + ['aquery'] + flags +
                               ['mnemonic("CppCompile", %s)' % ' + '.join(labels),
                                '--output=jsonproto'], cwd=ws)
        compile_actions = {}
        for action in json.loads(aquery)['actions']:
            argv = action['arguments']
            compile_actions[argv[argv.index('-o') + 1]] = argv
        flag_report = {}
        scratch = out / 'scratch'
        scratch.mkdir()
        for item in artifacts:
            listed = params_file(bazel_bin, item['bazel'])
            objects = [x for x in listed if x.endswith('.o')]
            dry = make_info[item['component']]['dry_run']
            per_object = {}
            for obj in objects:
                stem = re.sub(r'(\.pic)?\.o$', '', Path(obj).name)
                make_tokens = make_compile_command(dry, stem + item['make_object_suffix'],
                                                   by_basename=True)
                bazel_tokens = compile_actions[obj]
                mflags, mincludes, missing = normalize_make_compile(make_tokens, src)
                bflags, bincludes, dropped = normalize_bazel_compile(bazel_tokens)
                if mflags != bflags:
                    raise ValueError('compile flags differ from Make for %s: make-only %s bazel-only %s' %
                                     (obj, sorted(set(mflags) - set(bflags)),
                                      sorted(set(bflags) - set(mflags))))
                if mincludes != bincludes:
                    raise ValueError('include search path differs from Make for %s: %s vs %s' %
                                     (obj, mincludes, bincludes))
                make_object = Path(make_info[item['component']]['objdir']) / \
                    make_tokens[make_tokens.index('-o') + 1]
                ms = checker.sections(tools['llvm-objcopy'], readelf, make_object, scratch)
                bs = checker.sections(tools['llvm-objcopy'], readelf, ws / obj, scratch)
                differing = sorted(n for n in set(ms) | set(bs) if ms.get(n) != bs.get(n))
                strings = path_string_check(tools['llvm-objcopy'], make_object, ws / obj, src,
                                            scratch, ms, bs, differing)
                if not strings['explained']:
                    raise ValueError('object differs from Make beyond source-path strings: %s %s' %
                                     (obj, strings))
                per_object[stem] = {'make_object': str(make_object),
                                    'differing_sections': differing,
                                    'path_string_explanation': strings,
                                    'non_debug_differing_sections':
                                        [n for n in differing if '.debug_' not in n],
                                    'make_argv': make_tokens, 'bazel_argv': bazel_tokens,
                                    'compared_flags': bflags, 'include_order': bincludes,
                                    'make_include_dirs_absent_from_tree': missing,
                                    'bazel_only_tokens_explained': dropped}
            item_report = {'objects': per_object}
            if item['kind'] == 'program':
                mlink = make_link_command(dry, item['make'])
                blink = listed
                ms, bs = link_summary(mlink), link_summary(blink)
                if ms['options'] != bs['options'] or ms['libraries'] != bs['libraries'] or \
                        ms['objects'] != bs['objects']:
                    raise ValueError('link inputs/options differ from Make for ' + item['label'] +
                                     ': %s vs %s' % (ms, bs))
                item_report['link'] = {'make_argv': mlink, 'bazel_params': blink, 'make': ms,
                                       'bazel': bs,
                                       'library_order_equal': ms['libraries_order'] == bs['libraries_order']}
            flag_report[item['label']] = item_report
        result['compile_link_policy'] = {'status': 'matched', 'explanations': EXPLAINED_BAZEL_TOKENS}
        result['object_non_debug_differences'] = {
            label + ':' + stem: o['non_debug_differing_sections']
            for label, v in flag_report.items() for stem, o in v['objects'].items()
            if o['non_debug_differing_sections']}
        (out / 'compile-link-comparison.json').write_text(json.dumps(flag_report, indent=2) + '\n')
        result['compile_link_comparison_sha256'] = sha(out / 'compile-link-comparison.json')

        # ---- Artifact comparison and diagnostic relink. ----
        comparisons = {}
        for item in artifacts:
            make_artifact = Path(make_info[item['component']]['objdir']) / item['make']
            candidate = bazel_bin / item['bazel']
            if item['kind'] == 'archive':
                comparison = checker.compare_archive(tools['llvm-nm'], tools['llvm-ar'],
                                                     candidate, make_artifact)
            else:
                comparison = checker.compare_program(readelf, tools['llvm-objcopy'], candidate,
                                                     make_artifact, scratch)
                # Diagnostic only: relink the Bazel objects with Make's exact link
                # command to show which byte differences come from link order.
                mlink = flag_report[item['label']]['link']['make_argv']
                relinked = scratch / (Path(item['bazel']).name + '.make-order')
                argv = list(mlink)
                argv[argv.index('-o') + 1] = str(relinked)
                bazel_objects = {re.sub(r'(\.pic)?\.o$', '', Path(x).name): ws / x
                                 for x in params_file(bazel_bin, item['bazel']) if x.endswith('.o')}
                lib_dirs = {'-L' + str(out / 'make' / name): '-L' + str(bazel_bin / lib['bazel_dir'])
                            for name, lib in private_libs.items()}
                for index, token in enumerate(argv):
                    if token.endswith('.pieo'):
                        argv[index] = str(bazel_objects[Path(token).name[:-5]])
                    elif token in lib_dirs:
                        argv[index] = lib_dirs[token]
                buildenv(argv)
                relink_sections = checker.sections(tools['llvm-objcopy'], readelf, relinked, scratch)
                make_sections = comparison['make_reference']['sections']
                residual = sorted(n for n in set(relink_sections) | set(make_sections)
                                  if relink_sections.get(n) != make_sections.get(n))
                with open(make_artifact, 'rb') as stream:
                    make_bytes = stream.read()
                comparison['make_order_relink'] = {
                    'argv': argv, 'sha256': sha(relinked),
                    'differing_sections_vs_make': residual,
                    'non_debug_differences': [n for n in residual if not n.startswith('.debug_')
                                              and n not in ('.symtab', '.strtab')],
                    'make_embeds_absolute_source_path': (str(src) + '/').encode() in make_bytes}
            comparisons[item['label']] = comparison
        (out / 'artifact-comparison.json').write_text(json.dumps(comparisons, indent=2) + '\n')
        result['artifact_comparison_sha256'] = sha(out / 'artifact-comparison.json')
        result['artifact_summary'] = {
            label: {k: v for k, v in c.items() if k in ('byte_identical', 'needed_order_equal',
                                                        'differing_sections')} |
            ({'make_order_relink_non_debug_differences': c['make_order_relink']['non_debug_differences'],
              'make_embeds_absolute_source_path': c['make_order_relink']['make_embeds_absolute_source_path']}
             if 'make_order_relink' in c else {})
            for label, c in comparisons.items()}

        make_dir = out / 'make'
        rec.run([sys.executable, '-B', HERE / 'elf-artifact-check-test.py', '--readelf', readelf,
                 '--tools', sysroot / 'usr/bin', '--program', make_dir / 'hwstat/hwstat.full',
                 '--other-program', make_dir / 'otelexport_test/otelexport_test.full',
                 '--archive', library_dir / 'libotelexport_pie.a',
                 '--work', out / 'elf-artifact-check-test'])
        result['elf_artifact_checker_tests'] = 'passed'

        # ---- Negative dependency tests on copied inputs. ----
        negatives = []
        for probe in manifest['dependency_probes']:
            path = ws / probe['path']
            original, mode = path.read_bytes(), path.stat().st_mode
            path.chmod(mode | 0o200)  # SDK headers are installed read-only
            try:
                path.write_bytes(('#error ' + MARKER + '\n').encode() + original)
                _, stdout, stderr = rec.run(build, expect_success=False, cwd=ws)
                if MARKER not in stdout + stderr:
                    raise RuntimeError('failed for an unrelated reason: ' + probe['path'])
            finally:
                path.write_bytes(original)
                path.chmod(mode)
            rec.run(build, cwd=ws)
            negatives.append(dict(probe, injected_failure='observed', restored_build='passed'))
        for probe in manifest['link_probes']:
            path = ws / probe['path']
            link = os.readlink(path)
            try:
                path.unlink()
                path.write_text(LINK_MARKER + '\n')
                _, stdout, stderr = rec.run(build, expect_success=False, cwd=ws)
                if LINK_MARKER not in stdout + stderr:
                    raise RuntimeError('link failed for an unrelated reason: ' + probe['path'])
            finally:
                path.unlink()
                os.symlink(link, path)
            rec.run(build, cwd=ws)
            negatives.append(dict(probe, injected_failure='observed', restored_build='passed'))
        result['dependency_invalidation'] = negatives
        restored = {x['bazel']: sha(bazel_bin / x['bazel']) for x in artifacts}
        result['restored_outputs_identical'] = restored == outputs
        if restored != outputs:
            raise RuntimeError('outputs changed after restoring all probe inputs')

        # ---- Runtime fixture inputs for a matching-system VM runner. ----
        fixture = out / 'runtime-fixture'
        fixture.mkdir()
        fixture_manifest = {'programs': {}, 'libraries': {}}
        lib_dirs = [sysroot / 'lib', sysroot / 'usr/lib']
        for item in artifacts:
            if item['kind'] != 'program':
                continue
            name = Path(item['bazel']).name
            for variant, path in (('bazel', bazel_bin / item['bazel']),
                                  ('make', Path(make_info[item['component']]['objdir']) / name)):
                staged = fixture / (name if variant == 'bazel' else 'make-' + name)
                shutil.copy2(path, staged)
                staged.chmod(0o755)
                fixture_manifest['programs'][staged.name] = {'source': str(path), 'sha256': sha(staged)}
            for needed in comparisons[item['label']]['candidate']['metadata']['needed']:
                providers = [d / needed for d in lib_dirs if (d / needed).exists()]
                if not providers:
                    raise ValueError('SDK provider missing for ' + needed)
                fixture_manifest['libraries'][needed] = {'sdk_path': str(providers[0].resolve()),
                                                         'sha256': sha(providers[0])}
        fixture_manifest['note'] = ('Make variants are the stripped installed form; .full files are '
                                    'compared above. Stage these with the matching ld-elf.so.1 and '
                                    'the listed SDK libraries plus their own NEEDED closure.')
        (fixture / 'manifest.json').write_text(json.dumps(fixture_manifest, indent=2) + '\n')
        result['runtime_fixture'] = str(fixture)

        # ---- Host-ABI runtime (not matching-system qualification). ----
        if a.skip_host_runtime:
            result['host_runtime'] = 'not-performed'
        else:
            result['host_runtime'] = host_runtime(rec, out, fixture, src, artifacts)
        result['host_runtime_scope'] = ('host kernel ' + platform.release() + ' with host '
                                        'rtld/libraries; not the staged SDK runtime')
        for path, digest in result['probe_input_sha256'].items():
            if sha(path) != digest:
                raise RuntimeError('probe input changed during qualification: ' + path)
        changed = [p for p, d in source_digest.items() if not Path(p).is_file() or sha(p) != d]
        if changed:
            raise RuntimeError('source inputs changed during qualification: ' + ', '.join(changed[:10]))
        result['source_inputs_rechecked'] = len(source_digest)
        result['status'] = 'passed'
    except Exception as error:
        result.update(status='failed', error=str(error))
        raise
    finally:
        result['commands_sha256'] = sha(out / 'commands.json') if (out / 'commands.json').exists() else None
        save()
    print(out / 'result.json')


def host_runtime(rec, out, fixture, src, artifacts):
    report = {'status': 'passed', 'abi_blocked': []}
    work = out / 'host-runtime'
    work.mkdir()
    # Host rtld and host libraries; only libraries the host does not have
    # at all (new base libraries, for example libprivatenghttp2) come from
    # the staged SDK, through a directory holding just those.
    manifest = json.loads((fixture / 'manifest.json').read_text())
    sdk_only = work / 'sdk-only-libs'
    sdk_only.mkdir()
    for needed, info in sorted(manifest['libraries'].items()):
        if not (Path('/lib') / needed).exists() and not (Path('/usr/lib') / needed).exists():
            shutil.copy2(info['sdk_path'], sdk_only / needed)
    report['sdk_libraries_on_host'] = sorted(p.name for p in sdk_only.iterdir())
    env = dict(os.environ, LD_LIBRARY_PATH=str(sdk_only))

    def execute(argv, cwd=work):
        status, stdout, stderr = rec.run(argv, cwd=cwd, timeout=120, check=False, env=env)
        if ABI_FAILURE.search(stderr):
            report['abi_blocked'].append({'argv': [str(x) for x in argv], 'stderr': stderr})
        return status, stdout, stderr

    # ATF test programs: same case list and the same result in both builds;
    # every case passes, or is skipped identically (for example cases that
    # require root).  Source directories supply golden files (-s).
    cases = {}
    for item in artifacts:
        if not item.get('atf'):
            continue
        base = Path(item['bazel']).name
        srcdir = src / Path(item['bazel']).parent
        for name in (base, 'make-' + base):
            # ATF requires the program inside the source directory given
            # with -s: stage a copy of that directory with the program in it.
            staged = work / 'src' / name
            shutil.copytree(srcdir, staged, symlinks=False)
            shutil.copy2(fixture / name, staged / name)
            program = staged / name
            status, listing, _ = execute([program, '-l'])
            if status != 0:
                raise RuntimeError(name + ' could not list its test cases')
            idents = re.findall(r'^ident:\s+(\S+)$', listing, re.M)
            # require.user is honored as kyua does (ATF itself ignores it).
            needs = {}
            for block in listing.split('\n\n'):
                ident = re.search(r'^ident:\s+(\S+)$', block, re.M)
                user = re.search(r'^require\.user:\s+(\S+)$', block, re.M)
                if ident and user:
                    needs[ident.group(1)] = user.group(1)
            results = {}
            for case in idents:
                need = needs.get(case)
                if (need == 'root') != (os.getuid() == 0) and need in ('root', 'unprivileged'):
                    results[case] = 'skipped: requires %s user (kyua semantics)' % need
                    continue
                directory = work / name / case
                directory.mkdir(parents=True)
                execute([program, '-s', staged, '-r', directory / 'result', case], cwd=directory)
                results[case] = ((directory / 'result').read_text().strip()
                                 if (directory / 'result').exists() else 'no result file')
            # Failure messages carry __FILE__: absolute in Make, relative in Bazel.
            cases[name] = {k: v.replace(str(src) + '/', '') for k, v in results.items()}
        b, m = cases[base], cases['make-' + base]
        # expected_exit/expected_failure/... are ATF's passing outcomes.
        if b != m or any(not (v == 'passed' or v.startswith(('skipped:', 'expected_')))
                         for v in b.values()):
            raise RuntimeError('ATF results differ or failed for %s: %s' %
                               (base, json.dumps({base: b, 'make-' + base: m})))
    report['atf'] = cases

    def pair(name, args):
        runs = {}
        for variant in (name, 'make-' + name):
            status, stdout, stderr = execute([fixture / variant] + args)
            runs[variant] = {'exit_code': status, 'stdout': stdout, 'stderr': stderr}
        return runs[name], runs['make-' + name]

    checks = []
    for name, args in (('hwstat', []), ('hwstat', ['-h']), ('hwstat', ['bogus']),
                       ('bsdinstruments', []), ('bsdinstruments', ['-h']),
                       ('otelconf', []), ('otelconf', ['bogus']), ('otelpfd', ['extra']),
                       ('otelauditd', ['extra'])):
        b, m = pair(name, args)
        if b['exit_code'] != 2 or b != m:
            raise RuntimeError('usage behavior differs: %s %s' % (name, args))
        checks.append({'program': name, 'args': args, 'exit_code': 2, 'identical_output': True})
    otelconf_defaults = str(src / 'usr.sbin/otelconf/otel.conf.defaults')
    for name, args in (('bsdinstruments', ['list']), ('bsdinstruments', ['list', '--json']),
                       ('bsdinstruments', ['generate', 'accept-latency']),
                       ('otelconf', ['-d', otelconf_defaults, '-f', '', 'show']),
                       ('otelconf', ['-d', otelconf_defaults, '-f', '', 'get', 'endpoint'])):
        b, m = pair(name, args)
        if b['exit_code'] != 0 or b != m:
            raise RuntimeError('deterministic output differs: %s %s' % (name, args))
        checks.append({'program': name, 'args': args, 'exit_code': 0, 'identical_output': True,
                       'stdout_sha256': hashlib.sha256(b['stdout'].encode()).hexdigest()})
    b, m = pair('hwstat', ['list'])
    labels = [re.findall(r'^([A-Za-z][^:\n]*):', r['stdout'], re.M) for r in (b, m)]
    if b['exit_code'] != 0 or m['exit_code'] != 0 or labels[0] != labels[1]:
        raise RuntimeError('hwstat list output structure differs')
    checks.append({'program': 'hwstat', 'args': ['list'], 'exit_code': 0, 'labels': labels[0],
                   'note': 'live telemetry values vary between runs; field labels compared'})
    b, m = pair('hwstat', ['list', '--format', 'json'])
    shapes = [key_shape(json.loads(r['stdout'])) for r in (b, m)]
    if b['exit_code'] != 0 or m['exit_code'] != 0 or shapes[0] != shapes[1]:
        raise RuntimeError('hwstat JSON structure differs')
    checks.append({'program': 'hwstat', 'args': ['list', '--format', 'json'], 'exit_code': 0,
                   'json_shape_equal': True})
    b, m = pair('hwstat', ['watch', '--duration', '1', '--interval', '0.5'])
    if b['exit_code'] != 0 or m['exit_code'] != 0 or not b['stdout'] or not m['stdout']:
        raise RuntimeError('hwstat watch failed')
    checks.append({'program': 'hwstat', 'args': ['watch', '--duration', '1', '--interval', '0.5'],
                   'exit_code': 0, 'nonempty_output': True})
    report['program_checks'] = checks
    if report['abi_blocked']:
        report['status'] = 'blocked-host-abi'
    return report


if __name__ == '__main__':
    main()
