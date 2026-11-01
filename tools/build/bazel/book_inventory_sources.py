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
    root = Path(root)
    groups = {'man': [], 'sysctl': []}
    directories = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        relative_directory = os.path.relpath(directory, root)
        directories.append('.' if relative_directory == '.' else
                           Path(relative_directory).as_posix())
        # os.walk does not descend through symlink directories. Excluding .git
        # here mirrors check-book.sh's explicit prune and keeps its source view
        # finite. Inventory output is sorted below, so traversal order is free.
        dirs[:] = [name for name in dirs
                   if name != '.git' and
                   not os.path.islink(os.path.join(directory, name))]
        for name in files:
            is_man = (fnmatch.fnmatchcase(name, '*.[1-9]*') or
                      name == 'Makefile' or name.startswith('Makefile.') or
                      name.endswith('.mk'))
            is_sysctl_source = ((relative_directory == 'sys' or
                                 relative_directory.startswith('sys' + os.sep)) and
                                name.endswith(('.c', '.h')))
            if not (is_man or is_sysctl_source):
                continue
            path = os.path.join(directory, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            relative = Path(os.path.relpath(path, root)).as_posix()
            if is_man:
                groups['man'].append(relative)
            # Include all sys/ C and header files. The declared Bazel action
            # runs grep -l, so content changes that add or remove SYSCTL_ are
            # tracked as ordinary action inputs instead of repository-rule
            # content watches.
            if is_sysctl_source:
                groups['sysctl'].append(relative)
    return dict(groups={key: sorted(value) for key, value in groups.items()},
                directories=sorted(directories))


if __name__ == '__main__':
    print(json.dumps(inventory(Path(sys.argv[1]))))
