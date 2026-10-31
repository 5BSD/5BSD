#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Declared Bazel targets for cddl/lib/libdtrace and dtrace(1), compared with Make.

libdtrace.so.2 is built from its C and C++ sources plus the generated
dt_grammar.c/.h (staged bootstrap yacc), dt_lex.c (staged lex, which runs the
staged m4), dt_errtags.c, dt_names.c and priv.d (the shell generators, run
through stdout_redirect without a pipeline).  dtrace(1) links it.  The same
tree is built through maintained Make buildenv against the same staged SDK;
generated files, compile flags, include order, objects, link inputs and the
final ELF metadata are compared, and a negative dependency suite injects
failures into sources, headers, generator inputs and tools.  Not a system
build backend; build-bsd selects Make.
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
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bsd_toolchain  # noqa: E402


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


otel = load('otel_probe', 'otel-probe.py')
sha, Recorder, object_path = otel.sha, otel.Recorder, otel.object_path

MARKER = 'DTRACE_BAZEL_DEPENDENCY_PROBE'
LINK_MARKER = 'DTRACE_BAZEL_LINK_PROBE'

# Make component directories built for the reference, in dependency order.
MAKE_COMPONENTS = [
    # libotelexport's OTLP protobuf transport links the internal upb
    # library, which the dtrace link finds in the Make object tree.
    ('libupb', 'lib/protobuf/libupb', ['libupb_pie.a']),
    ('libotelexport', 'lib/libotelexport', ['libotelexport_pie.a']),
    ('libdtotel', 'cddl/lib/libdtotel', ['libdtotel_pie.a']),
    ('libdtrace', 'cddl/lib/libdtrace', ['libdtrace.so.2.full', 'priv.d']),
    ('dtrace', 'cddl/usr.sbin/dtrace', ['dtrace.full']),
]
PRIVATE_LIBS = {'libotelexport': 'LIBOTELEXPORTDIR', 'libdtotel': 'LIBDTOTELDIR'}

# Workspace inputs: whole component directories, header trees (*.h, *.hh)
# and individual source files outside the component directories.
COPY_DIRS = ['cddl/lib/libdtrace', 'cddl/usr.sbin/dtrace', 'cddl/lib/libdtotel',
             'lib/libotelexport', 'lib/protobuf/libupb']
# libotelexport's protobuf closure (upb, generated OTLP, nghttp2 and the
# protoc tools), as listed for the OTel probe.
OTEL_SOURCE_TREES = json.loads((HERE / 'targets/sources.json').read_text()).get('source_trees', [])
HEADER_TREES = ['sys', 'cddl/compat/opensolaris/include', 'cddl/contrib/opensolaris/head',
                'cddl/contrib/opensolaris/lib/libctf/common',
                'cddl/contrib/opensolaris/lib/libdtrace/common', 'usr.sbin/dtraced',
                'contrib/libucl/include']
SOURCE_GLOBS = ['cddl/contrib/opensolaris/lib/libdtrace/common/*.c',
                'cddl/contrib/opensolaris/lib/libdtrace/common/*.cc',
                'cddl/contrib/opensolaris/lib/libdtrace/common/*.y',
                'cddl/contrib/opensolaris/lib/libdtrace/common/*.l',
                'cddl/contrib/opensolaris/lib/libdtrace/common/*.sh',
                'cddl/contrib/opensolaris/lib/libdtrace/i386/dt_isadep.c',
                'cddl/contrib/opensolaris/lib/libgen/common/gmatch.c',
                'sys/cddl/dev/dtrace/x86/*.c',
                'cddl/contrib/opensolaris/cmd/dtrace/dtrace.c',
                'cddl/contrib/opensolaris/cmd/dtrace/*.h',
                'sys/sys/priv.h']
# Bootstrap tools from the staged SDK used by the generators (buildworld
# copies host tools it does not build into tmp/legacy; yacc is built).
GEN_TOOLS = ['yacc', 'lex', 'm4', 'sh', 'sed', 'awk', 'nawk', 'cat']

LIB_LABEL = '//cddl/lib/libdtrace:dtrace'
PROG_LABEL = '//cddl/usr.sbin/dtrace:dtrace'
GENERATED = {
    # Bazel output (relative to bazel-bin) -> Make objdir file.
    'cddl/lib/libdtrace/dt_grammar.c': 'dt_grammar.c',
    'cddl/lib/libdtrace/dt_grammar.h': 'dt_grammar.h',
    'cddl/lib/libdtrace/dt_lex.c': 'dt_lex.c',
    'cddl/lib/libdtrace/dt_errtags.c': 'dt_errtags.c',
    'cddl/lib/libdtrace/dt_names.c': 'dt_names.c',
    'cddl/lib/libdtrace/priv.d': 'priv.d',
}
GEN_LABELS = ['//cddl/lib/libdtrace:dt_grammar', '//cddl/lib/libdtrace:dt_lex',
              '//cddl/lib/libdtrace:dt_errtags', '//cddl/lib/libdtrace:dt_names',
              '//cddl/lib/libdtrace:priv_d']

COMMON = 'cddl/contrib/opensolaris/lib/libdtrace/common/'
# (path, kind, how): "prepend" injects #error MARKER; "yacc"/"lex" inject it
# into the C prologue (%{ %}); "script" makes the generator emit it; "tool"
# replaces a staged generator with one that fails naming the marker;
# "regenerate" changes a generator input and expects a different output.
DEPENDENCY_PROBES = [
    (COMMON + 'dt_aggregate.c', 'library C source', 'prepend'),
    (COMMON + 'dt_elf.cc', 'library C++ source', 'prepend'),
    (COMMON + 'dt_elf.hh', 'library C++ header', 'prepend'),
    (COMMON + 'dt_impl.h', 'library private header', 'prepend'),
    (COMMON + 'dtrace.h', 'library public header (also dtrace(1))', 'prepend'),
    ('cddl/lib/libdtrace/libproc_compat.h', 'Make-directory header (-I${.CURDIR})', 'prepend'),
    ('sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h', 'forced -include header', 'prepend'),
    ('sys/cddl/dev/dtrace/x86/dis_tables.h', 'kernel-tree disassembler header', 'prepend'),
    ('cddl/contrib/opensolaris/lib/libgen/common/gmatch.c', 'source from another .PATH directory', 'prepend'),
    (COMMON + 'dt_grammar.y', 'yacc grammar', 'yacc'),
    (COMMON + 'dt_lex.l', 'lex scanner', 'lex'),
    (COMMON + 'mkerrtags.sh', 'dt_errtags.c generator script', 'script'),
    (COMMON + 'mknames.sh', 'dt_names.c generator script', 'script'),
    (COMMON + 'dt_errtags.h', 'dt_errtags.c generator input (stdin), also a header', 'prepend'),
    ('sys/cddl/contrib/opensolaris/uts/common/sys/dtrace.h', 'dt_names.c generator input (stdin), also a header', 'prepend'),
    ('sys/sys/priv.h', 'priv.d generator input', 'regenerate'),
    ('cddl/lib/libdtrace/mkpriv', 'priv.d generator script', 'regenerate'),
    ('gentools/yacc', 'staged yacc tool', 'tool'),
    ('gentools/lex', 'staged lex tool', 'tool'),
    ('gentools/m4', 'staged m4 (run by lex)', 'tool'),
    ('gentools/sed', 'staged sed (run by mkerrtags.sh)', 'tool'),
    ('gentools/nawk', 'staged nawk (run by mknames.sh)', 'tool'),
    ('cddl/contrib/opensolaris/cmd/dtrace/dtrace.c', 'dtrace(1) source', 'prepend'),
    ('usr.sbin/dtraced/dtraced.h', 'dtraced header used by both', 'prepend'),
    ('cddl/lib/libdtotel/dtotel_session.h', 'libdtotel header used by dtrace(1)', 'prepend'),
    ('toolchain/sysroot/usr/include/libproc.h', 'SDK header (libproc)', 'prepend'),
    ('toolchain/sysroot/usr/include/libelf.h', 'SDK header (libelf)', 'prepend'),
]
LINK_PROBES = [
    ('toolchain/sysroot/usr/lib/libctf.so', 'SDK link input (libdtrace)'),
    ('toolchain/sysroot/usr/lib/librtld_db.so', 'SDK link input (libdtrace)'),
    ('toolchain/sysroot/usr/lib/libxo.so', 'SDK link input (dtrace)'),
]


def normalize_generated(text):
    """#line directives name the input and output by the path each build used."""
    return re.sub(r'^(#line \d+ ")([^"]*/)?([^"/]+)"', r'\1\3"', text, flags=re.M)


def link_summary(tokens, libraries_by_path):
    options, libraries, objects = set(), [], []
    output = tokens[tokens.index('-o') + 1] if '-o' in tokens else None
    for t in tokens:
        if t == output:
            continue
        if t.startswith('-Wl,'):
            options.update('-Wl,' + x for x in t[4:].split(','))
        elif t in ('-pie', '-gz=zlib', '-shared'):
            options.add(t)
        elif t.startswith('-l:'):
            libraries.append('-l' + re.sub(r'^lib|\.so(\.\d+)*$|\.a$', '', t[3:]))
        elif t.startswith('-l'):
            libraries.append(t)
        elif t in libraries_by_path:
            libraries.append(libraries_by_path[t])
        elif t.endswith('.a'):
            libraries.append('-l' + Path(t).name[3:-2])
        elif re.search(r'\.so(\.\d+)*$', t):
            libraries.append('-l' + re.sub(r'^lib|\.so(\.\d+)*$', '', Path(t).name))
        elif t.endswith('.o') or t.endswith('.pieo') or t.endswith('.pico'):
            objects.append(re.sub(r'(\.pic)?\.o$|\.pieo$|\.pico$', '', Path(t).name))
    ordered = list(dict.fromkeys(libraries))
    return {'options': sorted(options), 'libraries_order': ordered,
            'libraries': sorted(ordered), 'objects': objects}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('src', 'sysroot', 'objdump', 'awk', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--make', type=Path, default=Path('/usr/bin/make'))
    p.add_argument('--readelf', type=Path, default=Path('/usr/bin/readelf'))
    for name in ('target', 'cpu', 'clang-version'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--jobs', type=int, default=os.cpu_count())
    p.add_argument('--skip-negative', action='store_true',
                   help='skip the negative dependency suite (development only)')
    bsd_toolchain.add_bazel_arguments(p)
    a = p.parse_args()
    bzlmod = bsd_toolchain.prepare(p, a)
    if platform.system() != 'FreeBSD' or platform.machine() != 'amd64':
        p.error('native FreeBSD amd64 only')
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
    legacy = sysroot / 'legacy/usr/bin'
    tools = {'llvm-nm': sysroot / 'usr/bin/llvm-nm', 'llvm-ar': sysroot / 'usr/bin/llvm-ar',
             'llvm-objcopy': sysroot / 'usr/bin/llvm-objcopy'}
    gen_tools = {name: legacy / name for name in GEN_TOOLS}
    for path in [sysroot / 'usr/bin/clang', *tools.values(), *gen_tools.values()]:
        if not path.is_file():
            raise ValueError('staged tool missing: ' + str(path))
    out.mkdir(parents=True)
    rec = Recorder(out / 'commands.json')
    checker = load('elf_artifact_check', 'elf-artifact-check.py')
    probe_inputs = sorted([Path(__file__).resolve(), HERE / 'otel-probe.py', HERE / 'bsd_toolchain.py',
                           HERE / 'cc_toolchain_config.bzl', HERE / 'bsd_component.bzl',
                           HERE / 'cc_compat.bzl', bsd_toolchain.PINNED_LOCKFILE,
                           HERE / 'bsd_generate.bzl', HERE / 'stdout_redirect.c',
                           HERE / 'elf-artifact-check.py',
                           *sorted((HERE / 'targets').rglob('BUILD.bazel'))])
    result = {'scope': 'native-amd64-libdtrace-dtrace-declared-bazel-targets', 'status': 'running',
              'source_root': str(src), 'sysroot': str(sysroot), 'target': a.target,
              'jobs': a.jobs, 'production_backend': 'bsd-make',
              'probe_input_sha256': {str(x): sha(x) for x in probe_inputs},
              'tool_sha256': {str(x): sha(x) for x in (bazel, make, readelf, objdump, awk,
                                                        *tools.values(), *gen_tools.values())},
              'generator_tools': {name: str(path) for name, path in gen_tools.items()},
              'generator_tool_note': ('tmp/legacy of the staged world: yacc is built by '
                                      'buildworld; the others are host tools buildworld copies '
                                      'there, as Make buildenv uses them'),
              'system_backend_qualified': False,
              'cross_compilation_qualified': False, 'system_runtime_qualified': False,
              'installation_package_parity': False}

    def save():
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')

    source_files = set()
    for directory in COPY_DIRS + OTEL_SOURCE_TREES:
        source_files.update(f for f in (src / directory).rglob('*')
                            if f.is_file() and 'tests' not in f.relative_to(src / directory).parts)
    for tree in HEADER_TREES:
        source_files.update((src / tree).rglob('*.h'))
        source_files.update((src / tree).rglob('*.hh'))
    for pattern in SOURCE_GLOBS:
        source_files.update(src.glob(pattern))
    source_digest = {str(f): sha(f) for f in sorted(source_files)}
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

        make_info = {}
        for name, path, targets in MAKE_COMPONENTS:
            objdir = out / 'make' / name
            if name == 'libupb':
                # Where LIBUPBDIR (src.libnames.mk) points.
                objdir = (out / 'make/objprefix' / str(src).lstrip('/') / 'amd64.amd64' /
                          path)
            objdir.mkdir(parents=True)
            common = [var + '=' + str(out / 'make' / lib) for lib, var in PRIVATE_LIBS.items()
                      if lib != name]
            base = ['/usr/bin/env', 'MAKEOBJDIR=' + str(objdir), make, '-C', src / path]
            _, values, _ = buildenv(base + ['-V', 'SRCS', '-V', 'MK_CTF', '-V', 'MK_DTRACE_OPTIMIZED',
                                            '-V', 'MK_DTRACE_ASAN', '-V', 'MK_DTRACE_BENCHMARKS',
                                            '-V', 'MK_DTRACE_DEBUG_TSAN', '-V', 'DTRACE_TARGET_ARCH',
                                            '-V', 'SHLIB_NAME', '-V', 'YFLAGS'] + common)
            values = values.splitlines()[1:]
            _, dry, _ = buildenv(base + ['-n'] + targets + common)
            (out / 'make' / (name + '.dry-run.txt')).write_text(dry)
            buildenv(base + ['-j' + str(a.jobs)] + targets + common)
            make_info[name] = {'objdir': str(objdir), 'srcs': values[0].split(),
                               'knobs': dict(zip(['MK_CTF', 'MK_DTRACE_OPTIMIZED', 'MK_DTRACE_ASAN',
                                                  'MK_DTRACE_BENCHMARKS', 'MK_DTRACE_DEBUG_TSAN',
                                                  'DTRACE_TARGET_ARCH', 'SHLIB_NAME', 'YFLAGS'],
                                                 values[1:])),
                               'dry_run': dry}
        knobs = make_info['libdtrace']['knobs']
        result['make_knobs'] = {k: v['knobs'] for k, v in make_info.items()}
        if any(knobs[k] != 'no' for k in ('MK_CTF', 'MK_DTRACE_OPTIMIZED', 'MK_DTRACE_ASAN',
                                           'MK_DTRACE_BENCHMARKS')) or knobs['DTRACE_TARGET_ARCH']:
            raise ValueError('this probe models MK_CTF/DTRACE_* = no only: %s' % knobs)
        if knobs['SHLIB_NAME'] != 'libdtrace.so.2':
            raise ValueError('unexpected SHLIB_NAME ' + knobs['SHLIB_NAME'])

        # ---- Declared Bazel workspace. ----
        ws = out / 'workspace'
        ws.mkdir()
        bsd_toolchain.stage_toolchain(ws / 'toolchain', sysroot, objdump, awk,
                                      a.target, a.cpu, a.clang_version)
        bsd_toolchain.stage_repository_cache(bzlmod, out / 'repository-cache')
        for directory in COPY_DIRS + OTEL_SOURCE_TREES:
            # Test directories are not inputs of these targets.
            shutil.copytree(src / directory, ws / directory, symlinks=False, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns('tests', *bsd_toolchain.SOURCE_BAZEL_FILES))
        files = set()
        for tree in HEADER_TREES:
            files.update((src / tree).rglob('*.h'))
            files.update((src / tree).rglob('*.hh'))
        for pattern in SOURCE_GLOBS:
            files.update(src.glob(pattern))
        for path in sorted(files):
            if not path.resolve(strict=True).is_relative_to(src):
                raise ValueError('input escapes source tree: ' + str(path))
            destination = ws / path.relative_to(src)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
        gen = ws / 'gentools'
        gen.mkdir()
        for name, path in gen_tools.items():
            shutil.copy2(path, gen / name)
        shutil.copy2(HERE / 'stdout_redirect.c', gen / 'stdout_redirect.c')
        (gen / 'BUILD.bazel').write_text(
            'load("//toolchain:cc_toolchain_config.bzl", "bsd_static_binary")\n'
            'package(default_visibility=["//visibility:public"])\n'
            'exports_files(%s)\n' % json.dumps(GEN_TOOLS) +
            'filegroup(name="files", srcs=%s)\n' % json.dumps(GEN_TOOLS) +
            'bsd_static_binary(name="stdout_redirect", srcs=["stdout_redirect.c"])\n')
        for name in ('BUILD', 'BUILD.bazel', 'WORKSPACE', 'WORKSPACE.bazel', 'MODULE.bazel'):
            stray = [x for x in ws.rglob(name) if not (x.is_relative_to(ws / 'toolchain') or
                                                        x.is_relative_to(gen))]
            if stray:
                raise ValueError('source tree supplied its own Bazel file: ' + str(stray[0]))
        overlay = HERE / 'targets'
        for build_file in sorted(overlay.rglob('BUILD.bazel')):
            destination = ws / build_file.relative_to(overlay)
            if destination.parent == ws or destination.parent.is_dir():
                shutil.copy2(build_file, destination)
        bsd_toolchain.write_workspace(ws, 'bsd_dtrace_pilot', bzlmod)
        snapshot = {str(f.relative_to(ws)): sha(f) for f in sorted(ws.rglob('*')) if f.is_file()}
        (out / 'inputs.json').write_text(json.dumps(snapshot, indent=2) + '\n')
        result['inputs_sha256'] = sha(out / 'inputs.json')

        prefix = [bazel, '--batch', '--output_user_root=' + str(out / 'cache'), '--ignore_all_rc_files']
        flags = bsd_toolchain.build_flags(a.jobs, bzlmod) + ['--compilation_mode=opt', '--strip=never']
        labels = [LIB_LABEL, PROG_LABEL] + GEN_LABELS
        build = prefix + ['build'] + flags + labels
        result['bazel_version'] = rec.run(prefix + ['version'], cwd=ws)[1]
        result['bazel_mode'] = bsd_toolchain.mode_record(bzlmod)
        rec.run(build, cwd=ws)
        result['bazel_mode']['lockfile_unchanged'] = bsd_toolchain.lockfile_unchanged(ws, bzlmod)
        bazel_bin = ws / 'bazel-bin'
        lib_out = bazel_bin / 'cddl/lib/libdtrace/libdtrace.so.2'
        prog_out = bazel_bin / 'cddl/usr.sbin/dtrace/dtrace'
        outputs = {str(x.relative_to(bazel_bin)): sha(x) for x in
                   [lib_out, prog_out] + [bazel_bin / g for g in GENERATED]}
        result['bazel_outputs'] = outputs

        # ---- Generated-file parity with Make's object directory. ----
        mobj = Path(make_info['libdtrace']['objdir'])
        parity = {}
        for bazel_path, make_name in GENERATED.items():
            btext = (bazel_bin / bazel_path).read_text()
            mtext = (mobj / make_name).read_text()
            equal_raw = btext == mtext
            equal = normalize_generated(btext) == normalize_generated(mtext)
            parity[make_name] = {'byte_identical': equal_raw, 'identical_after_line_paths': equal,
                                 'bazel_sha256': sha(bazel_bin / bazel_path),
                                 'make_sha256': sha(mobj / make_name)}
            if not equal:
                raise ValueError('generated file differs from Make beyond #line paths: ' + make_name)
        result['generated_parity'] = parity

        # ---- Source list, compile flags and objects against Make. ----
        _, listed, _ = rec.run(prefix + ['query'] + bsd_toolchain.query_flags(bzlmod) + ['labels(srcs, %s)' % LIB_LABEL], cwd=ws)
        names = [Path(x.rsplit(':', 1)[1]).name for x in listed.split()]
        bazel_srcs = sorted(x for x in names if x.endswith(('.c', '.cc')) and
                            x != 'ccompile.h')
        # Rule outputs (dt_grammar, dt_lex, dt_errtags, dt_names) appear as targets.
        generated_targets = {'dt_grammar': 'dt_grammar.y', 'dt_lex': 'dt_lex.l',
                             'dt_errtags': 'dt_errtags.c', 'dt_names': 'dt_names.c'}
        bazel_srcs += [v for k, v in generated_targets.items() if k in names]
        # bsd.lib.mk rewrites a .y in SRCS to its .c and .h and a .l to its .c.
        make_srcs = [x for x in make_info['libdtrace']['srcs'] if not x.endswith('.h')]
        bazel_srcs = [re.sub(r'\.[yl]$', '.c', x) for x in bazel_srcs]
        if sorted(bazel_srcs) != sorted(make_srcs):
            raise ValueError('libdtrace BUILD srcs differ from Make SRCS: bazel-only %s make-only %s' %
                             (sorted(set(bazel_srcs) - set(make_srcs)),
                              sorted(set(make_srcs) - set(bazel_srcs))))
        result['srcs_match_make'] = {'libdtrace': make_srcs}

        _, aquery, _ = rec.run(prefix + ['aquery'] + flags +
                               ['mnemonic("CppCompile|CppLink", %s + %s)' % (LIB_LABEL, PROG_LABEL),
                                '--output=jsonproto'], cwd=ws)
        actions = json.loads(aquery)['actions']
        compile_actions, link_actions = {}, []
        for action in actions:
            argv = action['arguments']
            if '-c' in argv:
                compile_actions[argv[argv.index('-o') + 1]] = argv
            else:
                link_actions.append(argv)
        # Only objects that a link action consumes (aquery also lists the
        # unused PIC variant of a program object).
        linked = {t for x in link_actions for t in x if t.endswith('.o')}
        compile_actions = {k: v for k, v in compile_actions.items() if k in linked}
        scratch = out / 'scratch'
        scratch.mkdir()
        flag_report, bazel_objects = {}, {}
        for component, label_dir, suffix in (('libdtrace', 'cddl/lib/libdtrace', '.pico'),
                                             ('dtrace', 'cddl/usr.sbin/dtrace', '.pieo')):
            dry = make_info[component]['dry_run']
            per_object = {}
            for obj, bazel_tokens in sorted(compile_actions.items()):
                if not obj.startswith('bazel-out/') or '/' + label_dir + '/_objs/' not in obj:
                    continue
                stem = re.sub(r'(\.pic)?\.o$', '', Path(obj).name)
                bazel_objects.setdefault(component, {})[stem] = ws / obj
                make_tokens = otel.make_compile_command(dry, stem + suffix)
                mflags, mincludes, missing = otel.normalize_make_compile(make_tokens, src)
                bflags, bincludes, dropped = otel.normalize_bazel_compile(bazel_tokens)
                if mflags != bflags:
                    raise ValueError('compile flags differ from Make for %s: make %s bazel %s' %
                                     (obj, mflags, bflags))
                if mincludes != bincludes:
                    raise ValueError('include search path differs from Make for %s: %s vs %s' %
                                     (obj, mincludes, bincludes))
                make_object = Path(make_info[component]['objdir']) / (stem + suffix)
                ms = checker.sections(tools['llvm-objcopy'], readelf, make_object, scratch)
                bs = checker.sections(tools['llvm-objcopy'], readelf, ws / obj, scratch)
                differing = sorted(n for n in set(ms) | set(bs) if ms.get(n) != bs.get(n))
                strings = otel.path_string_check(tools['llvm-objcopy'], make_object, ws / obj, src,
                                                 scratch, ms, bs, differing)
                if not strings['explained']:
                    raise ValueError('object differs from Make beyond source-path strings: %s %s' %
                                     (obj, strings))
                per_object[stem] = {'make_object': str(make_object), 'differing_sections': differing,
                                    'path_string_explanation': strings,
                                    'non_debug_differing_sections':
                                        [n for n in differing if '.debug_' not in n],
                                    'make_argv': make_tokens, 'bazel_argv': bazel_tokens,
                                    'compared_flags': bflags, 'include_order': bincludes,
                                    'make_include_dirs_absent_from_tree': missing,
                                    'bazel_only_tokens_explained': dropped}
            flag_report[component] = {'objects': per_object}
        if len(flag_report['libdtrace']['objects']) != len(make_srcs) or \
                len(flag_report['dtrace']['objects']) != 1:
            raise ValueError('object count differs from Make SRCS')

        # Link inputs and order.
        # aquery arguments already hold the full command; the trailing
        # @params token repeats it for the linker driver.
        link_actions = [[t for t in x if not t.startswith('@')] for x in link_actions]
        lib_link = [x for x in link_actions if '-shared' in x]
        prog_link = [x for x in link_actions if '-shared' not in x]
        if len(lib_link) != 1 or len(prog_link) != 1:
            raise ValueError('expected one Bazel link action each for libdtrace and dtrace')
        lib_link, prog_link = lib_link[0], prog_link[0]
        by_path = {}
        for t in prog_link:
            if 'libdtrace.so' in t and not t.startswith('-'):
                by_path[t] = '-ldtrace'
        mlib = otel.make_link_command(make_info['libdtrace']['dry_run'], 'libdtrace.so.2.full')
        mprog = otel.make_link_command(make_info['dtrace']['dry_run'], 'dtrace.full')
        link_report = {}
        for name, mtokens, btokens in (('libdtrace', mlib, lib_link), ('dtrace', mprog, prog_link)):
            ms, bs = link_summary(mtokens, {}), link_summary(btokens, by_path)
            # The Make library links with the c++ driver, which adds the C++
            # runtime implicitly; the Bazel action names it explicitly.
            implicit = ['-lc++', '-lm'] if name == 'libdtrace' else []
            libs_equal = sorted(set(ms['libraries']) | set(implicit)) == bs['libraries']
            if ms['options'] != bs['options'] or not libs_equal or ms['objects'] != bs['objects']:
                raise ValueError('link inputs/options differ from Make for %s: %s vs %s' %
                                 (name, ms, bs))
            link_report[name] = {'make_argv': mtokens, 'bazel_argv': btokens, 'make': ms,
                                 'bazel': bs, 'make_driver_implicit_libraries': implicit,
                                 'library_order_equal': ms['libraries_order'] ==
                                 [x for x in bs['libraries_order'] if x not in implicit]}
        flag_report['link'] = link_report
        result['compile_link_policy'] = {'status': 'matched', 'explanations': otel.EXPLAINED_BAZEL_TOKENS}
        result['object_non_debug_differences'] = {
            c + ':' + stem: o['non_debug_differing_sections']
            for c in ('libdtrace', 'dtrace') for stem, o in flag_report[c]['objects'].items()
            if o['non_debug_differing_sections']}
        (out / 'compile-link-comparison.json').write_text(json.dumps(flag_report, indent=2) + '\n')
        result['compile_link_comparison_sha256'] = sha(out / 'compile-link-comparison.json')

        # ---- Artifact comparison. ----
        make_lib = mobj / 'libdtrace.so.2.full'
        make_prog = Path(make_info['dtrace']['objdir']) / 'dtrace.full'
        comparisons = {
            LIB_LABEL: checker.compare_shared(readelf, tools['llvm-objcopy'], lib_out, make_lib,
                                              'libdtrace.so.2', scratch),
            PROG_LABEL: checker.compare_program(readelf, tools['llvm-objcopy'], prog_out, make_prog,
                                                scratch),
        }
        # Diagnostic relink: the Bazel objects with Make's exact link commands.
        relinks = {}
        for name, mtokens, label in (('libdtrace', mlib, LIB_LABEL), ('dtrace', mprog, PROG_LABEL)):
            argv = list(mtokens)
            relinked = scratch / (name + '.make-order')
            argv[argv.index('-o') + 1] = str(relinked)
            for index, token in enumerate(argv):
                m = re.match(r'^(.*)\.(pico|pieo)$', token)
                if m:
                    argv[index] = str(bazel_objects[name][Path(m.group(1)).name])
                for lib, var in PRIVATE_LIBS.items():
                    if token == '-L' + str(out / 'make' / lib):
                        argv[index] = '-L' + str(bazel_bin / ('lib/libotelexport' if lib == 'libotelexport'
                                                             else 'cddl/lib/libdtotel'))
            buildenv(argv)
            relink_sections = checker.sections(tools['llvm-objcopy'], readelf, relinked, scratch)
            make_sections = comparisons[label]['make_reference']['sections']
            residual = sorted(n for n in set(relink_sections) | set(make_sections)
                              if relink_sections.get(n) != make_sections.get(n))
            relinks[name] = {'argv': argv, 'sha256': sha(relinked),
                             'differing_sections_vs_make': residual,
                             'non_debug_differences': [n for n in residual if not n.startswith('.debug_')
                                                       and n not in ('.symtab', '.strtab')]}
            comparisons[label]['make_order_relink'] = relinks[name]
        (out / 'artifact-comparison.json').write_text(json.dumps(comparisons, indent=2) + '\n')
        result['artifact_comparison_sha256'] = sha(out / 'artifact-comparison.json')
        result['artifact_summary'] = {
            label: {k: v for k, v in c.items() if k in ('byte_identical', 'needed_order_equal',
                                                        'differing_sections', 'exports_versioned')} |
            {'make_order_relink_non_debug_differences': c['make_order_relink']['non_debug_differences']}
            for label, c in comparisons.items()}

        # ---- Negative dependency tests on copied inputs. ----
        negatives = []
        if a.skip_negative:
            result['dependency_invalidation'] = 'skipped (development run)'
        else:
            for path_rel, kind, how in DEPENDENCY_PROBES:
                path = ws / path_rel
                original, mode = path.read_bytes(), path.stat().st_mode
                path.chmod(mode | 0o200)
                try:
                    if how == 'prepend':
                        path.write_bytes(('#error ' + MARKER + '\n').encode() + original)
                    elif how in ('yacc', 'lex'):
                        path.write_bytes(('%{\n#error ' + MARKER + '\n%}\n').encode() + original)
                    elif how == 'script':
                        path.write_bytes(original.replace(b'set -e\n', ('set -e\necho "#error ' + MARKER +
                                                                         '"\n').encode(), 1))
                        if MARKER.encode() not in path.read_bytes():
                            raise RuntimeError('script probe fixture: no "set -e" line in ' + path_rel)
                    elif how == 'tool':
                        path.write_bytes(('#!/bin/sh\necho ' + MARKER + ' >&2\nexit 1\n').encode())
                        path.chmod(0o755)
                    elif how == 'regenerate':
                        if path_rel == 'sys/sys/priv.h':
                            path.write_bytes(original + b'\n#define\tPRIV_DTRACE_BAZEL_PROBE\t99999\n')
                        else:
                            path.write_bytes(original.replace(b'NB: Mechanically generated',
                                                              b'NB: DTRACE_BAZEL_PROBE generated', 1))
                    if how == 'regenerate':
                        rec.run(prefix + ['build'] + flags + ['//cddl/lib/libdtrace:priv_d'], cwd=ws)
                        text = (bazel_bin / 'cddl/lib/libdtrace/priv.d').read_text()
                        if 'DTRACE_BAZEL_PROBE' not in text:
                            raise RuntimeError('priv.d was not regenerated from ' + path_rel)
                        observed = 'output regenerated'
                    else:
                        _, stdout, stderr = rec.run(build, expect_success=False, cwd=ws)
                        if MARKER not in stdout + stderr:
                            raise RuntimeError('failed for an unrelated reason: ' + path_rel)
                        observed = 'build failed with marker'
                finally:
                    path.write_bytes(original)
                    path.chmod(mode)
                rec.run(build, cwd=ws)
                negatives.append({'path': path_rel, 'kind': kind, 'injection': how,
                                  'injected_failure': observed, 'restored_build': 'passed'})
            for path_rel, kind in LINK_PROBES:
                path = ws / path_rel
                link = os.readlink(path)
                try:
                    path.unlink()
                    path.write_text(LINK_MARKER + '\n')
                    _, stdout, stderr = rec.run(build, expect_success=False, cwd=ws)
                    if LINK_MARKER not in stdout + stderr:
                        raise RuntimeError('link failed for an unrelated reason: ' + path_rel)
                finally:
                    path.unlink()
                    os.symlink(link, path)
                rec.run(build, cwd=ws)
                negatives.append({'path': path_rel, 'kind': kind, 'injected_failure': 'observed',
                                  'restored_build': 'passed'})
            result['dependency_invalidation'] = negatives
            restored = {k: sha(bazel_bin / k) for k in outputs}
            result['restored_outputs_identical'] = restored == outputs
            if restored != outputs:
                raise RuntimeError('outputs changed after restoring all probe inputs')

        # ---- Host usage check (no DTrace device is opened). ----
        usage = {}
        # Libraries from the staged SDK (built from this tree); the Bazel
        # variant finds its own libdtrace.so.2 first.  Host kernel and rtld.
        sdk_libs = [str(sysroot / 'lib'), str(sysroot / 'usr/lib')]
        for variant, prog, libdirs in (('bazel', prog_out, [str(lib_out.parent)] + sdk_libs),
                                       ('make', make_prog, sdk_libs)):
            env = {'PATH': '/bin:/usr/bin', 'LD_LIBRARY_PATH': ':'.join(libdirs)}
            status, stdout, stderr = rec.run([prog], env=env, check=False, timeout=60)
            # getprogname() differs (dtrace vs Make's dtrace.full).
            usage[variant] = {'exit_code': status,
                              'stderr': stderr.replace(str(prog), 'PROG').replace(prog.name, 'PROG', 1)}
        result['host_usage'] = usage
        result['host_usage_identical'] = usage['bazel'] == usage['make']
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


if __name__ == '__main__':
    main()
