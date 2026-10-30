# SPDX-License-Identifier: BSD-2-Clause
"""Invoke the shared version renderer without host metadata discovery."""
import argparse
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('script', 'param', 'copyright', 'template', 'identity', 'compiler', 'shell', 'path', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--branch', default='')
    parser.add_argument('--library', type=Path, action='append', default=[])
    args = parser.parse_args()
    if args.branch and not re.fullmatch(r'[A-Za-z0-9_.+-]+', args.branch):
        raise ValueError('branch override must be a version token')
    identity = args.identity.read_text().removesuffix('\n')
    if not identity or '\n' in identity:
        raise ValueError('configuration must supply exactly one kernel identity')
    compiler = subprocess.run([str(args.compiler.absolute()), '-v'],
        env={'LC_ALL': 'C'}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True)
    banner = '\n'.join(line for line in compiler.stdout.splitlines() if re.search(r'\bversion\b', line))
    if not banner:
        raise ValueError('selected compiler supplied no version banner')
    env = {'LC_ALL': 'C', 'PATH': str(args.path.absolute()),
           'PARAMFILE': str(args.param.absolute()),
           'NEWVERS_COPYRIGHT': str(args.copyright.absolute()),
           'NEWVERS_COPYRIGHT_TEMPLATE': str(args.template.absolute()),
           'NEWVERS_IDENT': identity, 'NEWVERS_COMPILER_VERSION': banner,
           'NEWVERS_SOURCE_REVISION': args.revision, 'BRANCH_OVERRIDE': args.branch}
    if args.library:
        env['LD_LIBRARY_PATH'] = ':'.join(dict.fromkeys(str(p.absolute().parent) for p in args.library))
    output = args.output.absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(args.shell.absolute()), str(args.script.absolute()), '-e'],
                   cwd=output.parent, env=env, check=True)
    if output.name != 'vers.c' or not output.is_file():
        raise ValueError('renderer did not produce the declared vers.c')


if __name__ == '__main__':
    main()
