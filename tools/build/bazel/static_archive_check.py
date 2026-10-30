#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Validate strong definitions using an explicitly selected LLVM nm tool.

Weak and common definitions are permitted by ELF linking semantics. GNU unique
symbols are coalesced too. GNU IFUNC (LLVM nm's lowercase i) is a strong definition.
This check does not establish archive ABI or runtime correctness.
"""
import argparse
import collections
import os
from pathlib import Path
import re
import subprocess


def duplicates(output):
    definitions = collections.defaultdict(list)
    for line in output.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'(.*\[[^\[\]]+\]): (\S+) ([A-Za-z?])(?: [0-9a-fA-F]+){0,2}', line)
        if not match:
            raise ValueError('unrecognized LLVM nm archive record: ' + line)
        member, symbol, kind = match.groups()
        if kind in 'UVWuvwCc':
            continue
        if kind == '?':
            raise ValueError('unknown symbol type: ' + line)
        definitions[symbol].append(member)
    return {name: owners for name, owners in sorted(definitions.items()) if len(owners) > 1}


def validate(nm, archive, output):
    # A failed retry must never retain an earlier success marker.
    output.unlink(missing_ok=True)
    result = subprocess.run([str(nm), '--format=posix', '--print-file-name',
                             '--extern-only', '--defined-only', str(archive)],
                            check=True, capture_output=True, text=True,
                            env={**os.environ, 'LC_ALL': 'C'})
    found = duplicates(result.stdout)
    if found:
        raise ValueError('duplicate strong definitions:\n' + '\n'.join(
            name + ': ' + ', '.join(owners) for name, owners in found.items()))
    output.write_text('strong archive definitions validated\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nm', required=True, type=Path)
    parser.add_argument('archive', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    validate(args.nm, args.archive, args.output)
