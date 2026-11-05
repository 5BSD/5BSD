#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Materialize one declared manual corpus and run the native database generator."""
import json
import os
from pathlib import Path
import posixpath
import shutil
import subprocess
import sys
import tempfile


def generate(request, executable, output):
    root = request['root']
    entries = {}
    for row in request['records']:
        path = row['destination']
        if not path.startswith(root + '/') or posixpath.normpath(path) != path:
            raise ValueError('manual destination escapes its root')
        relative = path[len(root) + 1:]
        if relative in entries or relative == 'mandoc.db':
            raise ValueError('duplicate or self-indexed manual')
        entries[relative] = row
    executable = str(Path(executable).absolute())
    output = Path(output).absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.manual-index-', dir=output.parent) as work:
        work = Path(work)
        for name in sorted(entries):
            path = work / name
            path.parent.mkdir(parents=True, exist_ok=True)
            row = entries[name]
            if row['type'] == 'file':
                shutil.copyfile(row['source'], path)
            elif row['type'] not in ('hardlink', 'symlink'):
                raise ValueError('unsupported manual object')
        for name, row in entries.items():
            if row['type'] != 'hardlink':
                continue
            target = request['hardlink_roots'].get(row['destination'], '')
            if not target.startswith(root + '/') or posixpath.normpath(target) != target:
                raise ValueError('hardlink root escapes manual corpus')
            relative = target[len(root) + 1:]
            if relative not in entries or entries[relative]['type'] != 'file':
                raise ValueError('undeclared regular manual hardlink root')
            os.link(work / relative, work / name)
        for name, row in entries.items():
            if row['type'] != 'symlink':
                continue
            target = row['link']
            absolute = posixpath.normpath(target if target.startswith('/') else posixpath.join(root, posixpath.dirname(name), target))
            if not absolute.startswith(root + '/') or absolute[len(root) + 1:] not in entries:
                raise ValueError('symlink target escapes or is absent from declared manual corpus')
            # Absolute installed aliases must remain inside the action's stage.
            actual = posixpath.relpath(absolute, posixpath.join(root, posixpath.dirname(name)))
            os.symlink(actual, work / name)
        for name, row in entries.items():
            if row['type'] == 'symlink':
                resolved = (work / name).resolve(strict=True)
                if not resolved.is_relative_to(work) or not resolved.is_file():
                    raise ValueError('manual symlink must resolve to a declared regular file')
        subprocess.run([executable, str(work)], check=True)
        database = work / 'mandoc.db'
        if not database.is_file():
            raise ValueError('nonempty declared corpus produced no manual database')
        shutil.copyfile(database, output)


if __name__ == '__main__':
    generate(json.loads(Path(sys.argv[1]).read_text()), sys.argv[2], sys.argv[3])
