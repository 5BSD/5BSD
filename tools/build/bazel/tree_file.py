# SPDX-License-Identifier: BSD-2-Clause
"""Copy a declared directory member, including Bazel sandbox input symlinks."""
from pathlib import Path
import shutil
import sys


def extract(tree, member, output):
    parts = member.split('/')
    if not member or '\\' in member or any(p in ('', '.', '..') for p in parts):
        raise ValueError('normalized relative member required')
    source = Path(tree)
    for part in parts:
        source = source / part
    if not source.is_file():
        raise ValueError('regular directory member required')
    shutil.copyfile(source, output)


if __name__ == '__main__':
    extract(*sys.argv[1:])
