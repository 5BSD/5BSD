#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Bazel compile pilot and Make installation reference; no system backend selection.

Bazel 9 or later only (Bzlmod, rules_cc, offline module inputs); the
executable defaults to /usr/local/bin/bazel and is version-checked before
any evidence output is created.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bsd_toolchain  # noqa: E402


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe_path(value, *, exists=True, object_path=False):
    if not value.is_absolute() or any(c in str(value) for c in '\n\r\x00$'):
        raise ValueError('paths must be absolute and contain no newline, NUL or Make dollar expansion')
    path = value.resolve(strict=exists)
    if object_path and (path == Path('/usr/obj') or not path.is_relative_to('/usr/obj')):
        raise ValueError('object and evidence paths must be below /usr/obj')
    return path


def parse_identity(output, objtop):
    lines = output.strip().splitlines()
    if len(lines) != 4 or lines[0] != 'Entering world for amd64:amd64':
        raise ValueError('unsupported or ambiguous Make buildenv identity: ' + output)
    if lines[1:] != [str(objtop), 'amd64', 'amd64']:
        raise ValueError('Make buildenv identity does not match explicit objtop')


def toolchain_identity(target, resource, sysroot):
    target = target.strip()
    if not re.fullmatch(r'x86_64-unknown-freebsd[0-9]+(?:\.[0-9]+)*', target):
        raise ValueError('only native amd64 FreeBSD toolchain targets are supported')
    directory = Path(resource.strip()).resolve(strict=True)
    parent = (sysroot / 'usr/lib/clang').resolve(strict=True)
    if directory.parent != parent or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', directory.name):
        raise ValueError('compiler resource directory does not match the staged sysroot')
    if not (directory / 'include').is_dir() or not any((directory / 'include').glob('*.h')):
        raise ValueError('staged compiler resource header directory is empty')
    return target, directory.name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('src', 'objtop', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    bsd_toolchain.add_bazel_arguments(parser)
    parser.add_argument('--jobs', type=int, required=True)
    parser.add_argument('--make', type=Path, default=Path('/usr/bin/make'))
    parser.add_argument('--readelf', type=Path, default=Path('/usr/bin/readelf'))
    args = parser.parse_args()
    if platform.system() != 'FreeBSD' or platform.machine() != 'amd64':
        parser.error('this pilot supports native FreeBSD amd64 only; cross compilation is unqualified')
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    src = safe_path(args.src)
    objtop = safe_path(args.objtop, object_path=True)
    output = safe_path(args.output, exists=False, object_path=True)
    if output.exists() or args.output.is_symlink():
        parser.error('--output must be a new evidence directory')
    if (output.is_relative_to(src) or output in src.parents or
            output in objtop.parents or output == objtop or
            output.is_relative_to(objtop / 'tmp')):
        parser.error('output must not overlap source or staged sysroot, or contain object inputs')
    bazel, make, readelf = (safe_path(p) for p in (args.bazel, args.make, args.readelf))
    bzlmod_inputs = safe_path(args.bzlmod_inputs)
    try:
        bazel_version = bsd_toolchain.check_bazel_version(bazel)
        offline = bsd_toolchain.load_bzlmod_inputs(bzlmod_inputs)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    scripts = src / 'tools/build/bazel'
    sysroot = objtop / 'tmp'
    clang = sysroot / 'usr/bin/clang'
    objdump = objtop / 'usr.bin/clang/llvm-objdump/llvm-objdump'
    awk = sysroot / 'legacy/usr/bin/awk'
    required = [bazel, make, readelf, clang, objdump, awk, bzlmod_inputs,
                scripts / 'declared-probe.py', scripts / 'bsd_toolchain.py',
                scripts / 'bzlmod/MODULE.bazel.lock', scripts / 'elf-shared-check-test.py',
                scripts / 'install-reference.py', scripts / 'libmd_environment.py',
                scripts / 'otel-probe.py', scripts / 'targets/sources.json',
                objtop / '.src_opts',
                src / 'Makefile', src / 'lib/libsbuf/Makefile',
                sysroot / 'usr/include/sys/sbuf.h']
    for path in required:
        if not path.is_file():
            raise ValueError('required staged input missing: ' + str(path))
    environment = {'PATH': '/bin:/usr/bin:/usr/local/bin', 'HOME': os.environ['HOME'],
                   'MAKEOBJDIRPREFIX': '/usr/obj', 'LC_ALL': 'C',
                   'SRCCONF': '/dev/null', '__MAKE_CONF': '/dev/null'}
    commands = []

    def run(command):
        completed = subprocess.run([str(x) for x in command], env=environment,
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        commands.append({'argv': [str(x) for x in command], 'status': completed.returncode,
                         'stdout': completed.stdout, 'stderr': completed.stderr})
        if output.is_dir():
            (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if completed.returncode:
            raise RuntimeError('command failed: ' + shlex.join([str(x) for x in command]) +
                               '\n' + completed.stdout + completed.stderr)
        return completed.stdout

    def buildenv(command):
        return run([make, '-C', src, 'buildenv', 'BUILDENV_SHELL=' + shlex.join([str(x) for x in command])])

    parse_identity(buildenv([make, '-C', src / 'lib/libsbuf', '-V', 'OBJTOP',
                             '-V', 'MACHINE', '-V', 'MACHINE_ARCH']), objtop)
    target, version = toolchain_identity(run([clang, '-dumpmachine']),
                                         run([clang, '-print-resource-dir']), sysroot)
    output.mkdir(parents=True, exist_ok=False)
    source_inputs = sorted(path for path in scripts.rglob('*')
                           if path.is_file() and path.suffix not in ('.pyc',))
    source_inputs += [src / path for path in ('bin/echo/echo.c',
        'lib/libc/string/strnlen.c', 'lib/libc/amd64/stdlib/div.S',
        'sys/kern/subr_prf.c', 'sys/kern/subr_sbuf.c', 'lib/libsbuf/Symbol.map',
        'lib/libsbuf/Version.def', 'lib/libsbuf/Makefile', 'share/mk/version_gen.awk')]
    otel_manifest = json.loads((scripts / 'targets/sources.json').read_text())
    for component in otel_manifest['components']:
        source_inputs += sorted(path for path in (src / component['path']).iterdir() if path.is_file())
    source_hashes = {str(path): sha(path) for path in source_inputs}
    receipt = {'scope': 'native-amd64-bazel-compile-qualification', 'status': 'running',
               'source': str(src), 'objtop': str(objtop), 'bazel': str(bazel),
               'jobs': args.jobs, 'target': target, 'clang_resource_version': version,
               'compile_only': False, 'bazel_compile_only': True,
               'make_install_reference': 'pending', 'otel_targets': 'pending',
               'runtime_qualified': False, 'system_backend_qualified': False,
               'bazel_version': bazel_version,
               'bazel_minimum_major': bsd_toolchain.MINIMUM_BAZEL_MAJOR,
               'bazel_modules': offline['modules'],
               'bzlmod_inputs': str(bzlmod_inputs),
               'repository_cache_digest': offline['repository_cache_digest'],
               'distdir_digest': offline['distdir_digest'],
               'production_backend': 'bsd-make',
               'remaining_inputs': ['host execution runtime and environment',
                                    'maintained Make configuration; not a hermetic build'],
               'tool_hashes': {str(path): sha(path) for path in (bazel, make, readelf, clang, objdump, awk,
                                                                 bzlmod_inputs)},
               'entrypoint_sha256': sha(Path(__file__)), 'source_hashes': source_hashes,
               'make_configuration': {'SRCCONF': '/dev/null', '__MAKE_CONF': '/dev/null'},
               'awk_resolved': str(awk.resolve(strict=True))}
    try:
        for name, component, artifact in (
                ('samples', scripts / 'shared-reference', 'libbsd_samples.so.1'),
                ('sbuf', src / 'lib/libsbuf', 'libsbuf.so.6')):
            directory = output / 'make' / name
            directory.mkdir(parents=True)
            buildenv(['/usr/bin/env', 'MAKEOBJDIR=' + str(directory), make, '-C', component,
                      '-j' + str(args.jobs), artifact])
        run([sys.executable, '-B', scripts / 'declared-probe.py', '--src', src,
             '--sysroot', sysroot, '--objdump', objdump, '--bazel', bazel,
             '--bzlmod-inputs', bzlmod_inputs,
             '--output', output / 'pilot', '--target', target, '--cpu', 'k8',
             '--clang-version', version, '--jobs', str(args.jobs), '--readelf', readelf,
             '--awk', awk, '--make-library', output / 'make/samples/libbsd_samples.so.1',
             '--make-sbuf-library', output / 'make/sbuf/libsbuf.so.6',
             '--make-sbuf-map', output / 'make/sbuf/Version.map'])
        # Declared OTel component targets against independent Make builds; compile and
        # artifact comparison only (host execution is left to explicit probe runs).
        run([sys.executable, '-B', scripts / 'otel-probe.py', '--src', src,
             '--sysroot', sysroot, '--objdump', objdump, '--awk', awk, '--bazel', bazel,
             '--bzlmod-inputs', bzlmod_inputs, '--make', make, '--readelf', readelf, '--target', target, '--cpu', 'k8',
             '--clang-version', version, '--jobs', str(args.jobs), '--skip-host-runtime',
             '--output', output / 'otel'])
        otel_result = json.loads((output / 'otel/result.json').read_text())
        if otel_result.get('status') != 'passed':
            raise RuntimeError('OTel Bazel target comparison did not pass')
        receipt.update(otel_targets='passed', otel_result_sha256=sha(output / 'otel/result.json'))
        run([sys.executable, '-B', scripts / 'elf-shared-check-test.py', '--readelf', readelf,
             '--reference', output / 'make/samples/libbsd_samples.so.1'])
        run([sys.executable, '-B', scripts / 'install-reference.py',
             '--src', src, '--objtop', objtop, '--profile', objtop / '.src_opts',
             '--component', src / 'lib/libmd', '--output', output / 'make-install-reference',
             '--jobs', str(args.jobs)])
        reference = output / 'make-install-reference/receipt.json'
        reference_result = json.loads(reference.read_text())
        if reference_result.get('status') != 'passed' or not reference_result.get('inputs_rechecked'):
            raise RuntimeError('Make installation reference did not complete with stable inputs')
        receipt.update(make_install_reference='passed',
                       make_install_reference_receipt_sha256=sha(reference))
        for path, expected in {**source_hashes, **receipt['tool_hashes']}.items():
            if sha(Path(path)) != expected:
                raise RuntimeError('input changed during qualification: ' + path)
        if sha(Path(__file__)) != receipt['entrypoint_sha256']:
            raise RuntimeError('entrypoint changed during qualification')
        receipt.update(status='passed', inputs_rechecked=True,
                       pilot_result_sha256=sha(output / 'pilot/result.json'))
    except Exception as error:
        receipt.update(status='failed', error=str(error))
        raise
    finally:
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        receipt['commands_sha256'] = sha(output / 'commands.json')
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(output / 'receipt.json')


if __name__ == '__main__':
    main()
