# SPDX-License-Identifier: BSD-2-Clause
"""Invoke the maintained loader version script with declared build inputs."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def text(value, name, nonempty=False):
    if not isinstance(value, str) or (nonempty and not value) or any(
        ord(c) < 32 or ord(c) == 127 or c in '\\"' for c in value):
        raise ValueError('C-string-safe build metadata required: ' + name)
    return value


def metadata(path):
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or set(value) - {'date', 'user', 'host', 'build_utc'} or not {'date', 'user', 'host'} <= set(value):
        raise ValueError('exact date/user/host and optional build_utc metadata required')
    result = {key: text(value[key], key, key == 'date') for key in ['date', 'user', 'host']}
    utc = value.get('build_utc', '')
    if not isinstance(utc, str) or (utc and (not utc.isascii() or not utc.isdecimal())):
        raise ValueError('build_utc must be an optional decimal string')
    result['build_utc'] = utc
    return result


def generate(args):
    tools = {name: getattr(args, name).resolve(strict=True) for name in ['shell', 'awk', 'mktemp', 'cat', 'mv', 'rm']}
    script = args.script.resolve(strict=True)
    version = args.version.resolve(strict=True)
    output = args.output.absolute()
    inputs = [script, version, *tools.values()]
    if args.metadata:
        inputs.append(args.metadata.resolve(strict=True))
    if output.resolve() in inputs or any(output.exists() and output.samefile(p) for p in inputs):
        raise ValueError('version output must not overwrite an input')
    description = text(args.description, 'description', True)
    machine = text(args.machine, 'machine', True)
    # Absolute declared commands leave no reason to search the execution host.
    env = {'PATH': '', 'LC_ALL': 'C'}
    for name in ['awk', 'mktemp', 'cat', 'mv', 'rm']:
        env['NEWVERS_' + name.upper()] = str(tools[name])
    if args.runtime:
        env['LD_LIBRARY_PATH'] = ':'.join(sorted({str(p.resolve(strict=True).parent) for p in args.runtime}))
    command = [str(tools['shell']), '-eu', str(script)]
    if args.reproducible:
        command.append('-r')
    else:
        if not args.metadata:
            raise ValueError('explicit build metadata required outside reproducible mode')
        values = metadata(args.metadata)
        env.update(NEWVERS_DATE=values['date'], USER=values['user'], HOSTNAME=values['host'], BUILD_UTC=values['build_utc'])
    command += ['-o', str(output), str(version), description, machine]
    try:
        subprocess.run(command, env=env, check=True)
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['shell', 'script', 'version', 'output', 'awk', 'mktemp', 'cat', 'mv', 'rm']:
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ['description', 'machine']:
        parser.add_argument('--' + name, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--reproducible', action='store_true')
    mode.add_argument('--metadata', type=Path)
    parser.add_argument('--runtime', action='append', type=Path, default=[])
    args = parser.parse_args()
    try:
        generate(args)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
