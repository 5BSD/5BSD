# SPDX-License-Identifier: BSD-2-Clause
"""Run pwd_mkdb on a private copy; never mutate the declared account input."""
import os
from pathlib import Path
import subprocess
import sys


def generate(tool, source, shells, destination):
    source = Path(source)
    destination = Path(destination)
    original = source.read_bytes()
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError('account generation directory must be empty')
    temporary = destination / 'input'
    with temporary.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(original)
    subprocess.run([tool, '-p', '-S', shells, '-d', str(destination), str(temporary)], check=True)
    expected = {'master.passwd': 0o600, 'passwd': 0o644,
                'pwd.db': 0o644, 'spwd.db': 0o600}
    if {p.name for p in destination.iterdir()} != set(expected):
        raise ValueError('unexpected account generator output inventory')
    for name, mode in expected.items():
        path = destination / name
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o7777 != mode:
            raise ValueError('invalid account output type or mode: ' + name)
    if source.read_bytes() != original or (destination / 'master.passwd').read_bytes() != original:
        raise ValueError('account input changed during generation')


if __name__ == '__main__':
    if len(sys.argv) != 5:
        raise SystemExit('usage: generate_accounts.py pwd_mkdb source shells output-directory')
    generate(*sys.argv[1:])
