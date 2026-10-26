#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Probe Bazel's native C toolchain; this is not a BSD system backend."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--bazel', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=os.cpu_count())
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    source = (args.src / 'bin/echo/echo.c').resolve(strict=True)
    bazel = args.bazel.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    workspace = output / 'workspace'
    workspace.mkdir()
    (workspace / 'WORKSPACE').write_text('workspace(name = "bsd_native_probe")\n')
    (workspace / 'BUILD.bazel').write_text(
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
    run(prefix + ['build', '--jobs=' + str(args.jobs), '--noshow_progress', '//:echo'])
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
        'executable_sha256': digest(executable), 'runtime_cases': len(cases),
        'jobs': args.jobs,
    }, indent=2) + '\n')
    print(output / 'result.json')


if __name__ == '__main__':
    main()
