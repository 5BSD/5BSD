# SPDX-License-Identifier: BSD-2-Clause
"""Expand the userland version template using the maintained newvers query."""
import argparse
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('newvers', 'param', 'template', 'shell', 'awk', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--branch', default='')
    args = parser.parse_args()
    if args.branch and not re.fullmatch(r'[A-Za-z0-9_.+-]+', args.branch):
        raise ValueError('branch override must be a version token')
    env = {'LC_ALL': 'C', 'PATH': str(args.awk.resolve().parent),
           'SYSDIR': str(args.param.resolve().parent.parent),
           'PARAMFILE': str(args.param.resolve()), 'BRANCH_OVERRIDE': args.branch}
    result = subprocess.run([str(args.shell.resolve()), str(args.newvers.resolve()), '-v'],
                            env=env, check=True, capture_output=True, text=True)
    values = {}
    for line in result.stdout.splitlines():
        match = re.fullmatch(r'([A-Z]+)="([A-Za-z0-9_.+ -]+)"', line)
        if not match or match[1] in values:
            raise ValueError('invalid newvers output')
        values[match[1]] = match[2]
    if set(values) != {'TYPE', 'REVISION', 'BRANCH', 'RELEASE', 'VERSION', 'RELDATE'}:
        raise ValueError('incomplete newvers output')
    content = args.template.read_text()
    for key in ('TYPE', 'REVISION', 'BRANCH'):
        if not re.fullmatch(r'[A-Za-z0-9_.+-]+', values[key]):
            raise ValueError('unsafe template version token')
        content = content.replace('@@' + key + '@@', values[key])
    if re.search(r'@@[A-Z]+@@', content):
        raise ValueError('unexpanded template marker')
    args.output.write_text(content)


if __name__ == '__main__':
    main()
