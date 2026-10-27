#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Verify selected native runtime libraries and execute a consumer without overrides.

This checks the named libraries only; other loader/system dependencies can remain
host supplied. It does not establish a hermetic runtime environment.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
from libmd_environment import digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--library', action='append', required=True, help='SONAME=declared artifact path')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--argument', action='append', default=[])
    parser.add_argument('--trace-only', action='store_true', help='verify a shared object loader trace without executing it')
    args = parser.parse_args()
    if args.trace_only and args.argument:
        raise ValueError('trace-only checks cannot have execution arguments')
    # Preserve the invocation path: test runners may launch a declared symlink.
    # Trace exactly that path rather than silently changing its loader origin.
    binary = args.binary.absolute()
    if not binary.resolve(strict=True).is_file():raise ValueError('consumer must be a file')
    out = args.output.resolve()
    if out.exists() or not out.is_relative_to('/usr/obj') or out == Path('/usr/obj'):
        raise ValueError('fresh output below /usr/obj required')
    expected = {}
    for item in args.library:
        name, separator, value = item.partition('=')
        if not separator or not name or '/' in name or name in expected:
            raise ValueError('unique SONAME=artifact entries required')
        expected[name] = Path(value).resolve(strict=True)
    out.mkdir()
    env = {'PATH': '/bin:/usr/bin', 'LC_ALL': 'C'}
    # FreeBSD ldd's default shared-object mode dlopens into its own process.
    # Explicit formats select a fresh rtld -d invocation, avoiding inherited
    # host libc/libsys mappings while preserving the standard trace syntax.
    trace_options = ['-f', '%o => %p (%x)\\n', '-f', '%o => %p (%x)\\n'] if args.trace_only else []
    trace = subprocess.run(['/usr/bin/ldd', *trace_options, str(binary)], env=env, text=True, capture_output=True)
    (out / 'loader.stdout').write_text(trace.stdout)
    (out / 'loader.stderr').write_text(trace.stderr)
    if trace.returncode:
        raise ValueError('loader trace failed')
    actual = {}
    for line in trace.stdout.splitlines():
        match = re.fullmatch(r'\s*(\S+)\s+=>\s+(\S+)\s+\([^)]*\)', line)
        if match:
            if match[1] in actual:
                raise ValueError('ambiguous loader result')
            actual[match[1]] = match[2]
    checks = {}
    for name, artifact in expected.items():
        if name not in actual or Path(actual[name]).resolve(strict=True) != artifact:
            raise ValueError('runtime resolved outside declared artifact: ' + name)
        checks[name] = dict(artifact=str(artifact), loader_path=actual[name], sha256=digest(artifact))
    if not args.trace_only:
        run = subprocess.run([str(binary), *args.argument], env=env, capture_output=True, text=True)
        (out / 'runtime.stdout').write_text(run.stdout)
        (out / 'runtime.stderr').write_text(run.stderr)
        if run.returncode:
            raise ValueError('consumer execution failed')
    for record in checks.values():
        if digest(Path(record['artifact'])) != record['sha256']:
            raise ValueError('runtime library changed during check')
    receipt = dict(status='passed', scope='named native runtime libraries; loader trace only' if args.trace_only else 'named native runtime libraries and consumer execution only',
                   execution_mode='trace-only' if args.trace_only else 'execute',
                   binary=str(binary), arguments=args.argument, binary_sha256=digest(binary), libraries=checks,
                   other_loader_libraries={k:v for k,v in actual.items() if k not in expected},
                   environment=env, driver_sha256=digest(Path(__file__)))
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('PASS:', len(checks), 'declared runtime libraries;', 'loader trace only' if args.trace_only else 'consumer executed')


if __name__ == '__main__':
    main()
