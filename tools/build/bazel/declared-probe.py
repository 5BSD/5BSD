#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Native amd64 C/C++/assembly static pilot, not a system build backend."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bsd_toolchain  # noqa: E402


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('src', 'sysroot', 'objdump', 'output', 'readelf', 'make-library', 'awk', 'make-sbuf-library', 'make-sbuf-map'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('target', 'cpu', 'clang-version'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--jobs', type=int, default=os.cpu_count())
    bsd_toolchain.add_bazel_arguments(p)
    a = p.parse_args()
    bzlmod = bsd_toolchain.prepare(p, a)
    if a.jobs < 1:
        p.error('--jobs must be positive')
    if not a.target.startswith('x86_64-'):
        p.error('the unmodified div.S fixture requires an amd64 target')
    src, sysroot = a.src.resolve(strict=True), a.sysroot.resolve(strict=True)
    bazel, objdump = a.bazel.resolve(strict=True), a.objdump.resolve(strict=True)
    root = a.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    workspace = root / 'workspace'
    workspace.mkdir()
    tc = workspace / 'toolchain'
    bsd_toolchain.stage_toolchain(tc, sysroot, objdump, a.awk.resolve(strict=True),
                                  a.target, a.cpu, a.clang_version)
    bsd_toolchain.stage_repository_cache(bzlmod, root / 'repository-cache')
    bsd_toolchain.write_workspace(workspace, 'bsd_declared_pilot', bzlmod)
    (workspace / 'BUILD.bazel').write_text(
        'load(":version_map.bzl", "bsd_version_map")\n'
        'load("//toolchain:cc_toolchain_config.bzl", "bsd_static_binary", "bsd_static_library", "bsd_shared_library", "bsd_dynamic_binary")\n'
        'bsd_static_binary(name="echo", srcs=["echo.c"])\n'
        'bsd_static_binary(name="cpp_runtime", srcs=["cpp_runtime.cc"], linkopts=["-lc++", "-lm", "-lpthread"])\n'
        'bsd_static_library(name="bsd_samples", srcs=["strnlen.c", "div.S"], copts=["-fno-builtin"])\n'
        'bsd_static_binary(name="archive_runtime", srcs=["archive_runtime.c"], deps=[":bsd_samples"], '
        'copts=["-fno-builtin"], linkopts=["-Wl,--trace-symbol=div,--trace-symbol=strnlen"])\n'
        'bsd_shared_library(name="libbsd_samples.so.1", soname="libbsd_samples.so.1", srcs=["strnlen.c", "div.S"], copts=["-fno-builtin"])\n'
        'bsd_dynamic_binary(name="shared_runtime", srcs=["shared_runtime.c"])\n'
        'bsd_dynamic_binary(name="sbuf_runtime", srcs=["sbuf_runtime.c"])\n')
    for local in ('stdout_redirect.c', 'version_map.bzl', 'sbuf_runtime.c'):
        shutil.copy2(Path(__file__).with_name(local), workspace / local)
    for origin, destination in [('sys/kern/subr_prf.c', 'subr_prf.c'),
                                ('sys/kern/subr_sbuf.c', 'subr_sbuf.c'),
                                ('lib/libsbuf/Symbol.map', 'sbuf-Symbol.map'),
                                ('lib/libsbuf/Version.def', 'sbuf-Version.def'),
                                ('share/mk/version_gen.awk', 'version_gen.awk')]:
        shutil.copy2(src / origin, workspace / destination)
    with (workspace / 'BUILD.bazel').open('a') as stream:
        stream.write('bsd_static_binary(name="stdout_redirect", srcs=["stdout_redirect.c"])\n')
        stream.write('bsd_version_map(name="sbuf_versions", symbols="sbuf-Symbol.map", '
                     'versions="sbuf-Version.def", generator="version_gen.awk", '
                     'compiler="//toolchain:bin/clang", compiler_inputs="//toolchain:compile_inputs", '
                     'awk="//toolchain:bin/awk", redirect=":stdout_redirect", target=' + json.dumps(a.target) + ')\n')
        stream.write('bsd_shared_library(name="libsbuf.so.6", soname="libsbuf.so.6", '
                     'srcs=["subr_prf.c", "subr_sbuf.c"], version_script=":sbuf_versions", '
                     'copts=["-O2", "-fno-common", "-std=gnu17", "-fstack-protector-strong"])\n')
    shutil.copy2(src / 'bin/echo/echo.c', workspace / 'echo.c')
    shutil.copy2(src / 'lib/libc/string/strnlen.c', workspace / 'strnlen.c')
    shutil.copy2(src / 'lib/libc/amd64/stdlib/div.S', workspace / 'div.S')
    shutil.copy2(Path(__file__).with_name('archive_runtime.c'), workspace / 'archive_runtime.c')
    (workspace / 'cpp_runtime.cc').write_text(
        '#include <vector>\n#include <iostream>\n'
        'int main() { std::vector<int> v{1,2,3}; std::cout << v.at(2) << "\\n"; }\n')
    shutil.copy2(Path(__file__).with_name('shared_runtime.c'), workspace / 'shared_runtime.c')
    snapshot = {str(f.relative_to(workspace)): sha(f)
                for f in workspace.rglob('*') if f.is_file()}
    (root / 'inputs.json').write_text(json.dumps(snapshot, indent=2) + '\n')
    records = []
    prefix = [str(bazel), '--batch', '--output_user_root=' + str(root / 'cache'),
              '--ignore_all_rc_files']
    build = prefix + ['build'] + bsd_toolchain.build_flags(a.jobs, bzlmod) + [
                      '//:echo', '//:cpp_runtime', '//:archive_runtime', '//:libbsd_samples.so.1', '//:shared_runtime', '//:sbuf_runtime', '//:libsbuf.so.6']

    def run(argv, expect_success=True):
        result = subprocess.run(argv, cwd=workspace, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        records.append({'argv': argv, 'exit_code': result.returncode, 'output': result.stdout})
        (root / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
        if (result.returncode == 0) != expect_success:
            raise RuntimeError('unexpected command result: ' + result.stdout)
        return result.stdout

    version = run(prefix + ['version'])
    output = run(build)
    for symbol in ('div', 'strnlen'):
        if not any('libbsd_samples.a' in line and 'definition of ' + symbol in line
                   for line in output.splitlines()):
            raise RuntimeError('archive member not proven to supply ' + symbol)
    members = run([str(tc / 'bin/llvm-ar'), 't', str(workspace / 'bazel-bin/libbsd_samples.a')])
    if (len(members.splitlines()) != 2 or
            {member.replace('.pic.o', '.o') for member in members.splitlines()} != {'div.o', 'strnlen.o'}):
        raise RuntimeError('unexpected archive members: ' + members)
    run([str(tc / 'bin/llvm-nm'), '--defined-only', str(workspace / 'bazel-bin/libbsd_samples.a')])
    # Exercise dependency invalidation on copied inputs, not the shared tree.
    for relative in ('echo.c', 'toolchain/sysroot/usr/include/sys/types.h',
                     'strnlen.c', 'div.S', 'toolchain/sysroot/usr/include/machine/asm.h'):
        path = workspace / relative
        original = path.read_bytes()
        try:
            path.write_bytes(b'#error BSD_BAZEL_DEPENDENCY_PROBE\n' + original)
            output = run(build, expect_success=False)
            if 'BSD_BAZEL_DEPENDENCY_PROBE' not in output:
                raise RuntimeError('failed for an unrelated reason: ' + output)
        finally:
            path.write_bytes(original)
        run(build)
    for relative, changed in [
            ('sbuf-Symbol.map', b'#error BSD_BAZEL_VERSION_PROBE\n'),
            ('sbuf-Version.def', b'BSD_BAZEL_VERSION_PROBE\n'),
            ('version_gen.awk', b'BEGIN { print "BSD_BAZEL_VERSION_PROBE" > "/dev/stderr"; exit 1 }\n')]:
        path = workspace / relative
        original = path.read_bytes()
        try:
            path.write_bytes(changed if relative == 'version_gen.awk' else changed + original)
            output = run(build, expect_success=False)
            if 'BSD_BAZEL_VERSION_PROBE' not in output:
                raise RuntimeError('unrelated version-input failure: ' + output)
        finally:
            path.write_bytes(original)
        run(build)
    build_file = workspace / 'BUILD.bazel'
    original = build_file.read_text()
    try:
        build_file.write_text(original +
            'bsd_static_binary(name="shared_rejected", srcs=["cpp_runtime.cc"], linkshared=True)\n')
        output = run(build, expect_success=False)
        if 'BSD pilot supports static executables only' not in output:
            raise RuntimeError('shared-target rejection failed: ' + output)
    finally:
        build_file.write_text(original)
    run(build)
    verifier = Path(__file__).with_name('elf-shared-check.py')
    spec = importlib.util.spec_from_file_location('elf_shared_check', verifier)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    shared_result = module.compare(a.readelf.resolve(strict=True),
        (workspace / 'bazel-bin/libbsd_samples.so.1').resolve(strict=True),
        a.make_library.resolve(strict=True), 'libbsd_samples.so.1')
    (root / 'shared-metadata.json').write_text(json.dumps(shared_result, indent=2) + '\n')
    generated_map = workspace / 'bazel-bin/sbuf_versions.map'
    if generated_map.read_bytes() != a.make_sbuf_map.read_bytes():
        raise RuntimeError('generated libsbuf version map differs from maintained Make output')
    version_verifier = Path(__file__).with_name('elf-version-check.py')
    spec = importlib.util.spec_from_file_location('elf_version_check', version_verifier)
    version_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(version_module)
    symbols = workspace / 'sbuf-Symbol.map'
    original_symbols = symbols.read_bytes()
    removed = b'\tsbuf_len;'
    if original_symbols.count(removed) != 1:
        raise RuntimeError('expected one real sbuf_len export')
    try:
        symbols.write_bytes(original_symbols.replace(removed, b'', 1))
        run(build)
        negative_library = root / 'libsbuf-missing-export.so.6'
        shutil.copyfile(workspace / 'bazel-bin/libsbuf.so.6', negative_library)
        try:
            version_module.compare(a.readelf.resolve(strict=True), negative_library,
                a.make_sbuf_library.resolve(strict=True), 'libsbuf.so.6')
        except ValueError as error:
            if str(error) != 'versioned exported interface differs from Make reference':
                raise
            negative_result = {'removed_export': 'sbuf_len', 'error': str(error),
                'library_sha256': sha(negative_library),
                'symbol_map_sha256': sha(symbols),
                'make_library_sha256': sha(a.make_sbuf_library)}
            (root / 'version-negative.json').write_text(
                json.dumps(negative_result, indent=2) + '\n')
        else:
            raise RuntimeError('missing real export was accepted')
    finally:
        symbols.write_bytes(original_symbols)
    run(build)
    if generated_map.read_bytes() != a.make_sbuf_map.read_bytes():
        raise RuntimeError('restored version map differs from Make output')
    version_result = version_module.compare(a.readelf.resolve(strict=True),
        (workspace / 'bazel-bin/libsbuf.so.6').resolve(strict=True),
        a.make_sbuf_library.resolve(strict=True), 'libsbuf.so.6')
    version_result['generated_map_sha256'] = sha(generated_map)
    version_result['make_map_path'] = str(a.make_sbuf_map.resolve(strict=True))
    version_result['make_map_sha256'] = sha(a.make_sbuf_map)
    (root / 'libsbuf-versioned.json').write_text(json.dumps(version_result, indent=2) + '\n')
    result = {'scope': 'native-amd64-archive-assembly-shared-pilot', 'bazel_version': version,
              'bazel_mode': dict(bsd_toolchain.mode_record(bzlmod),
                                 lockfile_unchanged=bsd_toolchain.lockfile_unchanged(workspace, bzlmod)),
              'bazel_sha256': sha(bazel), 'jobs': a.jobs, 'target': a.target,
              'inputs_sha256': sha(root / 'inputs.json'),
              'source_root': str(src), 'sysroot': str(sysroot), 'objdump': str(objdump),
              'toolchain_config': str(Path(__file__).with_name('cc_toolchain_config.bzl').resolve()),
              'probe_source': str(Path(__file__).resolve()),
              'probe_source_sha256': sha(Path(__file__)),
              'remaining_host_inputs': ['Bazel launcher and Java runtime',
                  'Bazel embedded build tools', 'host kernel and processwrapper sandbox',
                  'host executable runtime dependencies; not a hermeticity proof'],
              'outputs': {name: sha(workspace / 'bazel-bin' / name)
                          for name in ('echo', 'cpp_runtime', 'archive_runtime', 'libbsd_samples.a', 'libbsd_samples.so.1', 'shared_runtime', 'sbuf_runtime', 'libsbuf.so.6', 'sbuf_versions.map')},
              'source_and_header_invalidation': 'passed',
              'libsbuf_versioned_sha256': sha(root / 'libsbuf-versioned.json'),
              'version_inputs_invalidation': 'passed',
              'version_negative_sha256': sha(root / 'version-negative.json'),
              'awk_input': str(a.awk.resolve(strict=True)),
              'shared_metadata_sha256': sha(root / 'shared-metadata.json'),
              'shared_verifier_sha256': sha(verifier),
              'archive_member_link_provenance': ['strnlen', 'div'],
              'archive_members': members.splitlines(),
              'archive_sources': [str(src / 'lib/libc/string/strnlen.c'),
                                  str(src / 'lib/libc/amd64/stdlib/div.S')],
              'assembly_source_and_header_invalidation': 'passed', 'shared_target_rejected': True,
              'system_backend_qualified': False, 'runtime_qualified': False,
              'cross_compilation_qualified': False}
    (root / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(root / 'result.json')


if __name__ == '__main__':
    main()
