# SPDX-License-Identifier: BSD-2-Clause
"""Discover the regular-file inputs used by check-book.sh inventory modes.

Only repository evaluation calls this scanner. Build actions consume the
resulting declared labels; they never scan the original checkout.
"""
import fnmatch
import json
import os
from pathlib import Path
import sys


def inventory(root):
    groups = {'man': [], 'sysctl': []}
    directories = []
    entries = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        directories.append(Path(directory).relative_to(root).as_posix())
        entries.extend((Path(directory) / name).relative_to(root).as_posix()
                       for name in dirs + files if name != '.git')
        dirs[:] = sorted(name for name in dirs
                         if name != '.git' and not Path(directory, name).is_symlink())
        for name in sorted(files):
            path = Path(directory, name)
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if fnmatch.fnmatchcase(name, '*.[1-9]*') or name == 'Makefile' or name.startswith('Makefile.') or name.endswith('.mk'):
                groups['man'].append(relative)
            if relative.startswith('sys/') and name.endswith(('.c', '.h')):
                groups['sysctl'].append(relative)
    return dict(groups={key: sorted(value) for key, value in groups.items()},
                directories=sorted(directories), entries=sorted(entries))


if __name__ == '__main__':
    print(json.dumps(inventory(Path(sys.argv[1]))))
