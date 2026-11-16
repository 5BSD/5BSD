# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Discover the DQ checker's source namespace during repository evaluation.

The maintained checker scans C/header files across sys. Content filtering belongs
in that checker, never in discovery: adding a lookup to any existing file must
invalidate the action. Directory watches detect additions and deletions.
"""
import json
import os
from pathlib import Path
import stat
import sys


def inventory(root):
    root = Path(root)
    directories, files = [], []
    def fail(error):
        raise error
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=fail):
        relative = Path(directory).relative_to(root).as_posix()
        if relative != '.':
            directories.append(relative)
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError('DQ audit requires declared directory-link support: ' + str(Path(directory) / name))
        for name in names:
            if not name.endswith(('.c', '.h')):
                continue
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            # find/grep in the maintained checker have different link semantics.
            # Refuse an unsupported topology rather than silently under-scanning.
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError('DQ audit requires a regular C/header source: ' + relative)
            if any(c.isspace() or c in "\\'\"" for c in relative):
                raise ValueError('DQ checker cannot safely process source path: ' + relative)
            files.append(relative)
    if not files:
        raise ValueError('empty DQ source inventory')
    return dict(directories=sorted(directories), files=sorted(files))


if __name__ == '__main__':
    print(json.dumps(inventory(sys.argv[1])))
