#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Declared Bazel targets for the protobuf stack, compared with Make.

Builds Abseil (libprivateabsl.a and .so.2501), the protobuf C++ runtime
(libprivateprotobuf{,-lite}.a and .so.29, with the upstream version
scripts), libprotoc and libupb (INTERNALLIB archives), protoc and the three
upb plugins (installed PIE programs), libprivatenghttp2 (.a and .so.14) and
the OTLP bindings of lib/libotelexport (lib/protobuf/protoc-gen.mk, generated
by static exec-configuration builds of protoc and the plugins from the same
sources) with the declared staged toolchain, and the same directories through
maintained Make buildenv against the same staged SDK.  Source lists, compile
flags, include order, per-object non-debug sections, archive members, link
inputs, ELF metadata (SONAME, NEEDED, dynamic imports/exports with versions,
version definitions/requirements, hardening) and the generated files are
compared; a negative dependency suite injects failures into sources, headers,
a .proto, a generator, nghttp2's configuration headers, a version script and
SDK link inputs.  Not a system build backend; build-bsd selects Make.
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
import struct
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

MARKER = 'PROTOBUF_BAZEL_DEPENDENCY_PROBE'
LINK_MARKER = 'PROTOBUF_BAZEL_LINK_PROBE'

# Make component directories, their targets and the private INTERNALLIB
# directories their consumers are pointed at (LIB<NAME>DIR).
MAKE_COMPONENTS = [
    ('absl', 'lib/libabsl', ['libprivateabsl.a', 'libprivateabsl.so.2501.full']),
    ('protobuf_lite', 'lib/protobuf/libprotobuf-lite',
     ['libprivateprotobuf-lite.a', 'libprivateprotobuf-lite.so.29.full']),
    ('protobuf', 'lib/protobuf/libprotobuf',
     ['libprivateprotobuf.a', 'libprivateprotobuf.so.29.full']),
    ('libprotoc', 'lib/protobuf/libprotoc', ['libprotoc.a', 'libprotoc_pie.a']),
    ('upb', 'lib/protobuf/libupb', ['libupb.a', 'libupb_pie.a']),
    ('protoc', 'usr.bin/protoc', ['protoc.full']),
    ('protoc_gen_upb', 'libexec/protoc-gen-upb', ['protoc-gen-upb.full']),
    ('protoc_gen_upb_minitable', 'libexec/protoc-gen-upb_minitable',
     ['protoc-gen-upb_minitable.full']),
    ('protoc_gen_upbdefs', 'libexec/protoc-gen-upbdefs', ['protoc-gen-upbdefs.full']),
    ('nghttp2', 'lib/libnghttp2', ['libprivatenghttp2.a', 'libprivatenghttp2.so.14.full']),
    ('otlp', 'lib/libotelexport', ['protogen']),
]
PRIVATE_LIBS = {'libprotoc': 'LIBPROTOCDIR', 'upb': 'LIBUPBDIR'}

# label, kind, Make component, Make artifact, Bazel artifact (bazel-bin), SONAME.
ARTIFACTS = [
    ('//lib/libabsl:absl', 'archive', 'absl', 'libprivateabsl.a', 'lib/libabsl/libprivateabsl.a', None),
    ('//lib/libabsl:absl_so', 'shared', 'absl', 'libprivateabsl.so.2501.full',
     'lib/libabsl/libprivateabsl.so.2501', 'libprivateabsl.so.2501'),
    ('//lib/protobuf/libprotobuf-lite:protobuf_lite', 'archive', 'protobuf_lite',
     'libprivateprotobuf-lite.a', 'lib/protobuf/libprotobuf-lite/libprivateprotobuf-lite.a', None),
    ('//lib/protobuf/libprotobuf-lite:protobuf_lite_so', 'shared', 'protobuf_lite',
     'libprivateprotobuf-lite.so.29.full',
     'lib/protobuf/libprotobuf-lite/libprivateprotobuf-lite.so.29', 'libprivateprotobuf-lite.so.29'),
    ('//lib/protobuf/libprotobuf:protobuf', 'archive', 'protobuf', 'libprivateprotobuf.a',
     'lib/protobuf/libprotobuf/libprivateprotobuf.a', None),
    ('//lib/protobuf/libprotobuf:protobuf_so', 'shared', 'protobuf', 'libprivateprotobuf.so.29.full',
     'lib/protobuf/libprotobuf/libprivateprotobuf.so.29', 'libprivateprotobuf.so.29'),
    ('//lib/protobuf/libprotoc:protoc', 'archive', 'libprotoc', 'libprotoc.a',
     'lib/protobuf/libprotoc/libprotoc.a', None),
    ('//lib/protobuf/libprotoc:protoc_pie', 'archive', 'libprotoc', 'libprotoc_pie.a',
     'lib/protobuf/libprotoc/libprotoc_pie.a', None),
    ('//lib/protobuf/libupb:upb', 'archive', 'upb', 'libupb.a', 'lib/protobuf/libupb/libupb.a', None),
    ('//lib/protobuf/libupb:upb_pie', 'archive', 'upb', 'libupb_pie.a',
     'lib/protobuf/libupb/libupb_pie.a', None),
    ('//usr.bin/protoc:protoc', 'program', 'protoc', 'protoc.full', 'usr.bin/protoc/protoc', None),
    ('//libexec/protoc-gen-upb:protoc_gen_upb', 'program', 'protoc_gen_upb',
     'protoc-gen-upb.full', 'libexec/protoc-gen-upb/protoc-gen-upb', None),
    ('//libexec/protoc-gen-upb_minitable:protoc_gen_upb_minitable', 'program',
     'protoc_gen_upb_minitable', 'protoc-gen-upb_minitable.full',
     'libexec/protoc-gen-upb_minitable/protoc-gen-upb_minitable', None),
    ('//libexec/protoc-gen-upbdefs:protoc_gen_upbdefs', 'program', 'protoc_gen_upbdefs',
     'protoc-gen-upbdefs.full', 'libexec/protoc-gen-upbdefs/protoc-gen-upbdefs', None),
    ('//lib/libnghttp2:nghttp2', 'archive', 'nghttp2', 'libprivatenghttp2.a',
     'lib/libnghttp2/libprivatenghttp2.a', None),
    ('//lib/libnghttp2:nghttp2_so', 'shared', 'nghttp2', 'libprivatenghttp2.so.14.full',
     'lib/libnghttp2/libprivatenghttp2.so.14', 'libprivatenghttp2.so.14'),
]
GEN_LABEL = '//lib/libotelexport:otlp_gen'
GEN_DIR = 'lib/libotelexport/protogen/otlp'
# The c++ driver Make links LIB_CXX/PROG_CXX with adds the C++ runtime.
CXX_IMPLICIT = ['-lc++', '-lm']

# Workspace inputs, copied whole at their tree paths.
COPY_DIRS = ['contrib/abseil-cpp', 'contrib/protobuf', 'contrib/nghttp2',
             'contrib/opentelemetry-proto', 'lib/libabsl', 'lib/protobuf', 'lib/libnghttp2',
             'usr.bin/protoc', 'libexec/protoc-gen-upb', 'libexec/protoc-gen-upb_minitable',
             'libexec/protoc-gen-upbdefs', 'lib/libotelexport']

# (path, kind, how): "prepend" injects #error MARKER; "proto" adds a message
# named MARKER and expects it in the regenerated header; "map" injects the
# marker into a version script.
DEPENDENCY_PROBES = [
    ('contrib/abseil-cpp/absl/random/internal/randen_hwaes.cc', 'Abseil source with per-file flags', 'prepend'),
    ('contrib/abseil-cpp/absl/random/internal/randen_hwaes.h', 'Abseil header', 'prepend'),
    ('contrib/abseil-cpp/absl/base/options.h', 'Abseil configuration header (local patch)', 'prepend'),
    ('contrib/protobuf/src/google/protobuf/compiler/cpp/ifndef_guard.h', 'libprotoc header', 'prepend'),
    ('contrib/protobuf/src/google/protobuf/port_def.inc', 'protobuf port definitions (.inc)', 'prepend'),
    ('contrib/protobuf/third_party/utf8_range/utf8_range.h', 'utf8_range header (C and C++)', 'prepend'),
    ('contrib/protobuf/upb/wire/reader.h', 'upb header (library and generated code)', 'prepend'),
    ('contrib/protobuf/upb_generator/c/generator.cc', 'protoc-gen-upb source (exec tool)', 'prepend'),
    ('contrib/protobuf/upb_generator/reflection/generator.cc', 'protoc-gen-upbdefs source', 'prepend'),
    ('contrib/protobuf/upb_generator/cmake/google/protobuf/compiler/plugin.upb_minitable.c',
     'bootstrap plugin mini-table (C source)', 'prepend'),
    ('usr.bin/protoc/main.cc', 'protoc main (installed and exec tool)', 'prepend'),
    ('lib/libnghttp2/config.h', 'nghttp2 configuration header', 'prepend'),
    ('lib/libnghttp2/nghttp2/nghttp2ver.h', 'nghttp2 version header', 'prepend'),
    ('contrib/nghttp2/lib/nghttp2_session.c', 'nghttp2 source', 'prepend'),
    ('contrib/opentelemetry-proto/opentelemetry/proto/logs/v1/logs.proto', 'OTLP .proto', 'proto'),
    ('contrib/protobuf/src/libprotobuf.map', 'libprotobuf version script', 'map'),
    ('toolchain/sysroot/usr/include/zlib.h', 'SDK header (zlib, gzip_stream.cc)', 'prepend'),
]
LINK_PROBES = [
    ('toolchain/sysroot/usr/lib/libprivateabsl.so', 'SDK link input (protobuf, protoc, plugins)'),
    ('toolchain/sysroot/usr/lib/libprivateprotobuf.so', 'SDK link input (protoc)'),
    ('toolchain/sysroot/usr/lib/libz.so', 'SDK link input (libprivateprotobuf)'),
]


def elf_sections(path):
    """Section name -> sha256/size of an ELF64 little-endian file (in process;
    the per-section objcopy of elf-artifact-check.py is too slow for the
    thousands of COMDAT sections of these C++ objects).  Repeated names
    (.group, SHT_GROUP members) are numbered."""
    data = Path(path).read_bytes()
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        raise ValueError('not a little-endian ELF64 file: ' + str(path))
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    heads = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    stroff, strsize = heads[shstrndx][4], heads[shstrndx][5]
    names = data[stroff:stroff + strsize]
    result, seen = {}, {}
    for index, h in enumerate(heads):
        if index == 0 or h[1] in (0, 8):  # SHT_NULL, SHT_NOBITS
            continue
        name = names[h[0]:names.index(b'\0', h[0])].decode()
        n = seen.get(name, 0)
        seen[name] = n + 1
        key = name if n == 0 else '%s#%d' % (name, n)
        body = data[h[4]:h[4] + h[5]]
        result[key] = {'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body)}
    return result


def archive_members(ar, nm, path):
    """Members in order and the defined/undefined symbols of each, tolerant
    of the repeated basenames bsd.obj.mk subdirectories produce
    (absl/strings/escaping.o and absl/strings/internal/escaping.o)."""
    members = otel_run([ar, 't', path]).split()
    symbols, current, last = [], None, None
    for line in otel_run([nm, '-A', '--format=posix', path]).splitlines():
        m = re.match(r'^.*\[([^\]]+)\]:\s+(\S+)\s+(\S)\b', line)
        if not m:
            raise ValueError('unparsed nm line: ' + line)
        if m.group(1) != last:
            current = [m.group(1), []]
            symbols.append(current)
            last = m.group(1)
        current[1].append((m.group(2), m.group(3)))
    return members, [[n, sorted(s)] for n, s in symbols]


def otel_run(argv):
    import subprocess
    return subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, check=True, env={'PATH': '/bin:/usr/bin', 'LC_ALL': 'C'}).stdout


def member_stem(name):
    return re.sub(r'(\.pic)?\.o$|\.pieo$', '', name)


def link_summary(tokens, src):
    options, libraries, objects = set(), [], []
    output = tokens[tokens.index('-o') + 1] if '-o' in tokens else None
    for t in tokens:
        if t == output or t.startswith('@'):
            continue
        if t.startswith('-Wl,'):
            for x in t[4:].split(','):
                if x.startswith('--version-script='):
                    script = x.split('=', 1)[1]
                    x = '--version-script=' + (os.path.relpath(script, src) if script.startswith('/')
                                               else script)
                options.add('-Wl,' + x)
        elif t in ('-pie', '-gz=zlib', '-shared', '-static'):
            options.add(t)
        elif t.startswith('-l'):
            libraries.append(t)
        elif t.endswith('.a'):
            libraries.append('-l' + Path(t).name[3:-2])
        elif re.search(r'\.(o|pieo|pico)$', t):
            objects.append(re.sub(r'(\.pic)?\.o$|\.pieo$|\.pico$', '', Path(t).name))
    ordered = list(dict.fromkeys(libraries))
    return {'options': sorted(options), 'libraries_order': ordered,
            'libraries': sorted(ordered), 'objects': objects}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('src', 'sysroot', 'objdump', 'awk', 'bazel', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--make', type=Path, default=Path('/usr/bin/make'))
    p.add_argument('--readelf', type=Path, default=Path('/usr/bin/readelf'))
    for name in ('target', 'cpu', 'clang-version'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--jobs', type=int, default=os.cpu_count())
    p.add_argument('--skip-negative', action='store_true',
                   help='skip the negative dependency suite (development only)')
    bsd_toolchain.add_bazel_mode_arguments(p)
    a = p.parse_args()
    bzlmod = bsd_toolchain.load_bzlmod_inputs(a.bzlmod_inputs)
    bsd_toolchain.apply_bazel_environment(bzlmod)
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
    tools = {'llvm-nm': sysroot / 'usr/bin/llvm-nm', 'llvm-ar': sysroot / 'usr/bin/llvm-ar',
             'llvm-objcopy': sysroot / 'usr/bin/llvm-objcopy'}
    # Make generates the bindings with the bootstrap protoc and plugins of
    # the staged world (tmp/legacy, at the lib/protobuf/protobuf.dirs.mk
    # locations: all in /usr/libexec), as buildworld does.
    legacy = {name: sysroot / 'legacy/usr/libexec' / name for name in
              ('protoc', 'protoc-gen-upb', 'protoc-gen-upb_minitable', 'protoc-gen-upbdefs')}
    for path in [sysroot / 'usr/bin/clang', *tools.values(), *legacy.values()]:
        if not path.is_file():
            raise ValueError('staged tool missing: ' + str(path))
    out.mkdir(parents=True)
    rec = Recorder(out / 'commands.json')
    checker = load('elf_artifact_check', 'elf-artifact-check.py')
    probe_inputs = sorted([Path(__file__).resolve(), HERE / 'otel-probe.py', HERE / 'bsd_toolchain.py',
                           HERE / 'cc_toolchain_config.bzl', HERE / 'bsd_component.bzl',
                           HERE / 'cc_compat.bzl', HERE / 'cc_compat_bzlmod.bzl',
                           HERE / 'bsd_generate.bzl', HERE / 'bsd_cc.bzl',
                           HERE / 'elf-artifact-check.py',
                           *sorted((HERE / 'targets').rglob('BUILD.bazel'))])
    result = {'scope': 'native-amd64-protobuf-stack-declared-bazel-targets', 'status': 'running',
              'source_root': str(src), 'sysroot': str(sysroot), 'target': a.target,
              'jobs': a.jobs, 'production_backend': 'bsd-make',
              'probe_input_sha256': {str(x): sha(x) for x in probe_inputs},
              'tool_sha256': {str(x): sha(x) for x in (bazel, make, readelf, objdump, awk,
                                                        *tools.values(), *legacy.values())},
              'make_generator_tools': {k: str(v) for k, v in legacy.items()},
              'system_backend_qualified': False, 'bazel9_qualified': False,
              'cross_compilation_qualified': False, 'system_runtime_qualified': False,
              'installation_package_parity': False}

    def save():
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')

    source_files = set()
    for directory in COPY_DIRS:
        source_files.update(f for f in (src / directory).rglob('*')
                            if f.is_file() and 'tests' not in f.relative_to(src / directory).parts)
    source_files.update((src / 'contrib/libucl/include').glob('*.h'))
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

        _, env_out, _ = buildenv(['/usr/bin/env'])
        if not any(x.startswith('CC=') and '--sysroot=' + str(sysroot) in x
                   for x in env_out.splitlines()):
            raise ValueError('Make buildenv does not use the explicit staged sysroot')
        make_info = {}
        for name, path, targets in MAKE_COMPONENTS:
            objdir = out / 'make' / name
            objdir.mkdir()
            common = [var + '=' + str(out / 'make' / lib) for lib, var in PRIVATE_LIBS.items()
                      if lib != name]
            base = ['/usr/bin/env', 'MAKEOBJDIR=' + str(objdir), make, '-C', src / path]
            _, values, _ = buildenv(base + ['-V', 'SRCS'] + common)
            _, dry, _ = buildenv(base + ['-n'] + targets + common)
            (out / 'make' / (name + '.dry-run.txt')).write_text(dry)
            buildenv(base + ['-j' + str(a.jobs)] + targets + common)
            make_info[name] = {'objdir': str(objdir), 'srcs': values.splitlines()[1].split(),
                               'dry_run': dry}
        result['make_reference'] = {k: {'objdir': v['objdir'], 'srcs': v['srcs']}
                                    for k, v in make_info.items()}

        # ---- Declared Bazel workspace. ----
        ws = out / 'workspace'
        ws.mkdir()
        bsd_toolchain.stage_toolchain(ws / 'toolchain', sysroot, objdump, awk,
                                      a.target, a.cpu, a.clang_version, bzlmod)
        for directory in COPY_DIRS:
            shutil.copytree(src / directory, ws / directory, symlinks=False, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns('tests', *bsd_toolchain.SOURCE_BAZEL_FILES))
        (ws / 'contrib/libucl/include').mkdir(parents=True)
        for header in (src / 'contrib/libucl/include').glob('*.h'):
            shutil.copy2(header, ws / 'contrib/libucl/include' / header.name)
        for name in ('BUILD', 'BUILD.bazel', 'WORKSPACE', 'WORKSPACE.bazel', 'MODULE.bazel'):
            stray = [x for x in ws.rglob(name) if not x.is_relative_to(ws / 'toolchain')]
            if stray:
                raise ValueError('source tree supplied its own Bazel file: ' + str(stray[0]))
        overlay = HERE / 'targets'
        for build_file in sorted(overlay.rglob('BUILD.bazel')):
            destination = ws / build_file.relative_to(overlay)
            if destination.parent == ws or destination.parent.is_dir():
                shutil.copy2(build_file, destination)
        bsd_toolchain.write_workspace(ws, 'bsd_protobuf_pilot', bzlmod)
        snapshot = {str(f.relative_to(ws)): sha(f) for f in sorted(ws.rglob('*')) if f.is_file()}
        (out / 'inputs.json').write_text(json.dumps(snapshot, indent=2) + '\n')
        result['inputs_sha256'] = sha(out / 'inputs.json')

        prefix = [bazel, '--batch', '--output_user_root=' + str(out / 'cache'), '--ignore_all_rc_files']
        flags = bsd_toolchain.build_flags(a.cpu, a.jobs, bzlmod) + ['--compilation_mode=opt', '--strip=never']
        labels = [x[0] for x in ARTIFACTS] + [GEN_LABEL]
        build = prefix + ['build'] + flags + ['--output_groups=+manifest'] + labels
        result['bazel_version'] = rec.run(prefix + ['version'], cwd=ws)[1]
        result['bazel_mode'] = bsd_toolchain.mode_record(bzlmod)
        rec.run(build, cwd=ws)
        if bzlmod:
            result['bazel_mode']['lockfile_unchanged'] = (
                sha(ws / 'MODULE.bazel.lock') == sha(Path(bzlmod['lockfile'])))
        bazel_bin = ws / 'bazel-bin'
        manifests = {}
        for label, kind, *_ in ARTIFACTS:
            pkg, name = label[2:].split(':')
            manifests[label] = json.loads((bazel_bin / pkg / (name + '.objects.json')).read_text())
        gen_outputs = sorted(f.relative_to(bazel_bin / GEN_DIR) for f in (bazel_bin / GEN_DIR).rglob('*')
                             if f.is_file())
        outputs = {x[4]: sha((bazel_bin / x[4]).resolve()) for x in ARTIFACTS}
        outputs.update({GEN_DIR + '/' + str(f): sha(bazel_bin / GEN_DIR / f) for f in gen_outputs})
        result['bazel_outputs'] = outputs

        # ---- Source lists in BUILD files must equal Make SRCS (in order). ----
        def srcs_check():
            report = {}
            for label, kind, component, *_ in ARTIFACTS:
                pkg, name = label[2:].split(':')
                listed = json.loads((bazel_bin / pkg / (name + '.objects.json')).read_text())['srcs']
                if listed != make_info[component]['srcs']:
                    raise ValueError('BUILD srcs differ from Make SRCS for %s: bazel-only %s make-only %s' %
                                     (label, sorted(set(listed) - set(make_info[component]['srcs'])),
                                      sorted(set(make_info[component]['srcs']) - set(listed))))
                report[label] = len(listed)
            return report

        result['srcs_match_make'] = srcs_check()
        build_file = ws / 'lib/libabsl/BUILD.bazel'
        original_build = build_file.read_text()
        try:
            entry = '    "absl/strings/cord.cc",\n'
            if original_build.count(entry) != 1:
                raise RuntimeError('drift-guard fixture expects one cord.cc entry')
            build_file.write_text(original_build.replace(entry, '', 1))
            rec.run(prefix + ['build'] + flags + ['--output_groups=manifest', '//lib/libabsl:absl'],
                    cwd=ws)
            try:
                srcs_check()
            except ValueError as error:
                result['srcs_drift_rejected'] = str(error)
            else:
                raise RuntimeError('removed BUILD source was not detected')
        finally:
            build_file.write_text(original_build)
            rec.run(prefix + ['build'] + flags + ['--output_groups=manifest', '//lib/libabsl:absl'],
                    cwd=ws)
        srcs_check()

        # ---- Generated OTLP bindings against Make's (byte for byte). ----
        mgen = Path(make_info['otlp']['objdir']) / 'protogen/otlp'
        make_gen = sorted(f.relative_to(mgen) for f in mgen.rglob('*')
                          if f.is_file() and f.name != '.stamp')
        if make_gen != gen_outputs:
            raise ValueError('generated file sets differ: bazel-only %s make-only %s' %
                             (sorted(map(str, set(gen_outputs) - set(make_gen))),
                              sorted(map(str, set(make_gen) - set(gen_outputs)))))
        parity = {}
        for f in gen_outputs:
            equal = (bazel_bin / GEN_DIR / f).read_bytes() == (mgen / f).read_bytes()
            parity[str(f)] = {'byte_identical': equal, 'sha256': sha(mgen / f)}
            if not equal:
                raise ValueError('generated file differs from Make: ' + str(f))
        result['generated_parity'] = {'files': len(parity), 'all_byte_identical': True,
                                      'files_detail': parity,
                                      'make_generator': 'staged world tmp/legacy protoc and plugins',
                                      'bazel_generator': 'static exec-configuration protoc_tool and '
                                                         '*_tool plugins built in this workspace'}
        otlp_srcs = [x for x in make_info['otlp']['srcs'] if x.startswith('protogen/')]
        if sorted(x[len('protogen/otlp/'):] for x in otlp_srcs) != \
                sorted(str(f) for f in gen_outputs if f.name.endswith(('.upb_minitable.c', '.upbdefs.c'))):
            raise ValueError('generated sources in Make SRCS differ from the compiled Bazel set')

        # ---- Compile flags and objects. ----
        _, aquery, _ = rec.run(prefix + ['aquery'] + flags +
                               ['mnemonic("CppCompile|CppLink", set(%s))' %
                                ' '.join(x[0] for x in ARTIFACTS), '--output=jsonproto'], cwd=ws)
        compile_actions, link_actions = {}, {}
        for action in json.loads(aquery)['actions']:
            argv = action['arguments']
            if '-c' in argv:
                compile_actions[argv[argv.index('-o') + 1]] = argv
            elif '-o' in argv:
                link_actions[argv[argv.index('-o') + 1]] = [t for t in argv if not t.startswith('@')]
        scratch = out / 'scratch'
        scratch.mkdir()
        flag_report, object_differences, compared = {}, {}, 0
        for label, kind, component, *_ in ARTIFACTS:
            dry = make_info[component]['dry_run']
            per_object = {}
            for make_path, bazel_path in manifests[label]['objects'].items():
                make_tokens = otel.make_compile_command(dry, make_path)
                bazel_tokens = compile_actions[bazel_path]
                mflags, mincludes, missing = otel.normalize_make_compile(make_tokens, src)
                bflags, bincludes, dropped = otel.normalize_bazel_compile(bazel_tokens)
                if mflags != bflags:
                    raise ValueError('compile flags differ from Make for %s: make %s bazel %s' %
                                     (make_path, mflags, bflags))
                if mincludes != bincludes:
                    raise ValueError('include search path differs from Make for %s: %s vs %s' %
                                     (make_path, mincludes, bincludes))
                make_object = Path(make_info[component]['objdir']) / make_path
                ms, bs = elf_sections(make_object), elf_sections(ws / bazel_path)
                differing = sorted(n for n in set(ms) | set(bs) if ms.get(n) != bs.get(n))
                strings = otel.path_string_check(tools['llvm-objcopy'], make_object, ws / bazel_path,
                                                 src, scratch, ms, bs,
                                                 [n for n in differing if '#' not in n])
                renamed = [n for n in differing if '#' in n and not n.startswith('.debug_')]
                if not strings['explained'] or renamed:
                    raise ValueError('object differs from Make beyond source-path strings: %s %s %s' %
                                     (make_path, strings, renamed))
                nondebug = [n for n in differing if '.debug_' not in n]
                if nondebug:
                    object_differences[label + ':' + make_path] = nondebug
                per_object[make_path] = {'differing_sections': differing,
                                         'non_debug_differing_sections': nondebug,
                                         'path_string_explanation': strings,
                                         'compared_flags': bflags, 'include_order': bincludes,
                                         'make_include_dirs_outside_tree': missing,
                                         'bazel_only_tokens_explained': dropped}
                compared += 1
            flag_report[label] = {'objects': per_object}
        result['objects_compared'] = compared
        result['object_non_debug_differences'] = object_differences
        result['compile_link_policy'] = {'status': 'matched', 'explanations': otel.EXPLAINED_BAZEL_TOKENS}

        # ---- Link inputs and artifacts. ----
        comparisons = {}
        for label, kind, component, make_name, bazel_name, soname in ARTIFACTS:
            make_artifact = Path(make_info[component]['objdir']) / make_name
            candidate = (bazel_bin / bazel_name).resolve()
            if kind == 'archive':
                mm, msym = archive_members(tools['llvm-ar'], tools['llvm-nm'], make_artifact)
                bm, bsym = archive_members(tools['llvm-ar'], tools['llvm-nm'], candidate)
                if [member_stem(x) for x in mm] != [member_stem(x) for x in bm]:
                    raise ValueError('archive member order differs from Make for ' + label)
                if [[member_stem(n), s] for n, s in msym] != [[member_stem(n), s] for n, s in bsym]:
                    raise ValueError('archive member symbols differ from Make for ' + label)
                comparisons[label] = {'scope': 'archive-member-symbol-comparison',
                                      'members': len(mm), 'make_sha256': sha(make_artifact),
                                      'bazel_sha256': sha(candidate),
                                      'byte_identical': sha(make_artifact) == sha(candidate)}
                continue
            mlink = otel.make_link_command(make_info[component]['dry_run'], make_name)
            blink = [v for k, v in link_actions.items()
                     if Path(k).resolve() == candidate or Path(ws / k).resolve() == candidate]
            if len(blink) != 1:
                raise ValueError('expected one Bazel link action for ' + label)
            ms, bs = link_summary(mlink, src), link_summary(blink[0], src)
            cxx = any(x.endswith('.cc') for x in make_info[component]['srcs'])
            implicit = CXX_IMPLICIT if cxx else []
            if ms['options'] != bs['options'] or \
                    sorted(set(ms['libraries']) | set(implicit)) != bs['libraries'] or \
                    ms['objects'] != bs['objects']:
                raise ValueError('link inputs/options differ from Make for %s: %s vs %s' %
                                 (label, ms, bs))
            if kind == 'shared':
                comparison = checker.compare_shared(readelf, tools['llvm-objcopy'], candidate,
                                                    make_artifact, soname, scratch)
            else:
                comparison = checker.compare_program(readelf, tools['llvm-objcopy'], candidate,
                                                     make_artifact, scratch)
            comparison['link'] = {'make_argv': mlink, 'bazel_argv': blink[0], 'make': ms, 'bazel': bs,
                                  'make_driver_implicit_libraries': implicit,
                                  'library_order_equal': ms['libraries_order'] ==
                                  [x for x in bs['libraries_order'] if x not in implicit]}
            # Section bodies are recorded by compare_*; keep the report small.
            for side in ('candidate', 'make_reference'):
                comparison[side].pop('sections', None)
            comparisons[label] = comparison
        (out / 'compile-comparison.json').write_text(json.dumps(flag_report, indent=2) + '\n')
        (out / 'artifact-comparison.json').write_text(json.dumps(comparisons, indent=2) + '\n')
        result['compile_comparison_sha256'] = sha(out / 'compile-comparison.json')
        result['artifact_comparison_sha256'] = sha(out / 'artifact-comparison.json')
        result['artifact_summary'] = {
            label: {k: v for k, v in c.items() if k in ('byte_identical', 'needed_order_equal',
                                                        'differing_sections', 'exports_versioned',
                                                        'members')} |
            ({'library_order_equal': c['link']['library_order_equal']} if 'link' in c else {})
            for label, c in comparisons.items()}

        # ---- Negative dependency tests on copied inputs. ----
        if a.skip_negative:
            result['dependency_invalidation'] = 'skipped (development run)'
        else:
            negatives = []
            for path_rel, kind, how in DEPENDENCY_PROBES:
                path = ws / path_rel
                original, mode = path.read_bytes(), path.stat().st_mode
                path.chmod(mode | 0o200)
                try:
                    if how == 'prepend':
                        path.write_bytes(('#error ' + MARKER + '\n').encode() + original)
                    elif how == 'proto':
                        path.write_bytes(original + ('\nmessage ' + MARKER + ' {}\n').encode())
                    elif how == 'map':
                        # "NAME { ... }" is a valid named version node, so
                        # the marker alone would link; "NAME;" is a syntax
                        # error that lld reports with the offending line.
                        path.write_bytes((MARKER + ';\n').encode() + original)
                    if how == 'proto':
                        rec.run(prefix + ['build'] + flags + [GEN_LABEL], cwd=ws)
                        text = (bazel_bin / GEN_DIR / 'opentelemetry/proto/logs/v1/logs.upb.h').read_text()
                        if MARKER not in text:
                            raise RuntimeError('logs.upb.h was not regenerated from ' + path_rel)
                        observed = 'bindings regenerated with the injected message'
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
            restored = {k: sha((bazel_bin / k).resolve()) for k in outputs}
            result['restored_outputs_identical'] = restored == outputs
            if restored != outputs:
                raise RuntimeError('outputs changed after restoring all probe inputs')

        # ---- Host runtime (host kernel and rtld, SDK libraries). ----
        sdk_env = {'PATH': '/bin:/usr/bin', 'LC_ALL': 'C',
                   'LD_LIBRARY_PATH': '%s:%s' % (sysroot / 'lib', sysroot / 'usr/lib')}
        runtime = {}
        mprotoc = Path(make_info['protoc']['objdir']) / 'protoc.full'
        bprotoc = bazel_bin / 'usr.bin/protoc/protoc'
        for variant, prog in (('bazel', bprotoc), ('make', mprotoc)):
            _, version, _ = rec.run([prog, '--version'], env=sdk_env, timeout=60)
            gen = scratch / ('cpp-' + variant)
            gen.mkdir()
            rec.run([prog, '-I' + str(src / 'contrib/protobuf/src'), '--cpp_out=' + str(gen),
                     str(src / 'contrib/protobuf/src/google/protobuf/descriptor.proto')],
                    env=sdk_env, timeout=120)
            runtime[variant] = {'version': version.strip(),
                                'cpp_out_sha256': {str(f.relative_to(gen)): sha(f)
                                                   for f in sorted(gen.rglob('*')) if f.is_file()}}
        runtime['identical'] = runtime['bazel'] == runtime['make']
        if not runtime['identical']:
            raise RuntimeError('protoc runtime behavior differs between the builds')
        runtime['scope'] = ('host kernel %s, host rtld, SDK libraries via LD_LIBRARY_PATH; '
                            'descriptor.proto --cpp_out from both builds' % platform.release())
        result['host_runtime'] = runtime

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
