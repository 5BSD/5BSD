# SPDX-License-Identifier: BSD-2-Clause
"""Run the two maintained tzdata AWK passes with the declared version input."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    for name in ['awk', 'guard', 'shrink', 'version', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('sources', nargs='+', type=Path)
    args = parser.parse_args()
    lines = args.version.read_text().splitlines()
    if len(lines) != 1 or not lines[0].strip() or '\0' in lines[0]:
        raise ValueError('one explicit tzdata version line required')
    with tempfile.TemporaryFile(dir=args.output.parent) as intermediate:
        subprocess.run([str(args.awk), '-v', 'DATAFORM=main', '-v', 'PACKRATDATA=', '-v',
                        'PACKRATLIST=', '-f', str(args.guard), *map(str, args.sources)],
                       check=True, stdout=intermediate, env=dict(os.environ, LC_ALL='C'))
        intermediate.seek(0)
        with args.output.open('wb') as output:
            subprocess.run([str(args.awk), '-v', 'dataform=main', '-v', 'deps=zishrink.awk',
                            '-v', 'redo=posix_only', '-v', 'version=' + lines[0].strip(),
                            '-f', str(args.shrink)], check=True, stdin=intermediate,
                           stdout=output, env=dict(os.environ, LC_ALL='C'))


if __name__ == '__main__':
    main()
