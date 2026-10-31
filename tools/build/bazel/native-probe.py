#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Probe Bazel's native C toolchain; this is not a BSD system backend.

Bazel 9 or later with Bzlmod: rules_cc's autodetected host toolchain,
offline module inputs (--bzlmod-inputs) and the pinned lockfile.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bsd_toolchain  # noqa: E402


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=os.cpu_count())
    bsd_toolchain.add_bazel_arguments(parser)
    args = parser.parse_args()
    bzlmod = bsd_toolchain.prepare(parser, args, host_toolchain=True)
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    source = (args.src / 'bin/echo/echo.c').resolve(strict=True)
    bazel = args.bazel.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    workspace = output / 'workspace'
    workspace.mkdir()
    bsd_toolchain.stage_repository_cache(bzlmod, output / 'repository-cache')
    bsd_toolchain.write_workspace(workspace, 'bsd_native_probe', bzlmod, staged_toolchain=False)
    (workspace / 'BUILD.bazel').write_text(
        'load("@rules_cc//cc:defs.bzl", "cc_binary")\n'
        'cc_binary(name = "echo", srcs = ["echo.c"], linkopts = ["-static"])\n')
    (workspace / 'echo.c').write_bytes(source.read_bytes())
    commands = []

    def run(argv):
        result = subprocess.run(argv, cwd=workspace, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        commands.append({'argv': [str(x) for x in argv],
                         'returncode': result.returncode, 'output': result.stdout})
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if result.returncode:
            raise RuntimeError(result.stdout)
        return result.stdout

    prefix = [str(bazel), '--batch', '--output_user_root=' + str(output / 'cache'),
              '--ignore_all_rc_files']
    version = run(prefix + ['version'])
    run(prefix + ['build', '--jobs=' + str(args.jobs), '--noshow_progress'] +
        bsd_toolchain.repository_flags(bzlmod) + ['//:echo'])
    executable = workspace / 'bazel-bin/echo'
    cases = [([], '\n'), (['hello', 'world'], 'hello world\n'),
             (['-n', 'hello'], 'hello'), (['-e', 'hello'], '-e hello\n')]
    for argv, expected in cases:
        actual = run([str(executable)] + argv)
        if actual != expected:
            raise RuntimeError('echo output mismatch: ' + repr((argv, actual, expected)))
    if digest(source) != digest(workspace / 'echo.c'):
        raise RuntimeError('source changed during qualification')
    (output / 'result.json').write_text(json.dumps({
        'scope': 'native-host-toolchain-smoke-only',
        'system_backend_qualified': False, 'cross_compilation_qualified': False,
        'source': str(source), 'source_sha256': digest(source),
        'bazel': str(bazel), 'bazel_sha256': digest(bazel), 'version': version,
        'bazel_mode': dict(bsd_toolchain.mode_record(bzlmod),
                           lockfile_unchanged=bsd_toolchain.lockfile_unchanged(workspace, bzlmod)),
        'executable_sha256': digest(executable), 'runtime_cases': len(cases),
        'jobs': args.jobs,
    }, indent=2) + '\n')
    print(output / 'result.json')


if __name__ == '__main__':
    main()
