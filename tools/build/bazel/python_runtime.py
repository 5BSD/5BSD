# SPDX-License-Identifier: BSD-2-Clause
"""Inventory an explicitly selected Python standard library for build actions."""
import json
import os
from pathlib import Path
import subprocess


def inventory(interpreter, stdlib):
    interpreter = Path(interpreter).resolve(strict=True)
    stdlib = Path(stdlib).resolve(strict=True)
    if not stdlib.is_dir():
        raise ValueError('Python standard library must be a directory')
    command = [str(interpreter), '-I', '-S', '-c',
               'import sys,json; print(json.dumps(list(sys.version_info[:2])))']
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    major, minor = json.loads(result.stdout)
    version = 'python%d.%d' % (major, minor)
    if stdlib.name != version or not (stdlib / 'encodings/__init__.py').is_file():
        raise ValueError('selected standard library does not match the interpreter version')
    files = {}
    for current, directories, names in os.walk(stdlib):
        directories[:] = sorted(name for name in directories if name not in ('site-packages', '__pycache__'))
        if any((Path(current) / name).is_symlink() for name in directories):
            raise ValueError('Python standard-library directory symlinks require explicit materialization')
        for name in sorted(names):
            path = Path(current) / name
            if not path.is_file() or path.suffix in ('.pyc', '.pyo'):
                continue
            if not path.resolve(strict=True).is_relative_to(stdlib):
                raise ValueError('Python standard-library symlink escapes selected tree')
            files['python-home/lib/' + version + '/' + str(path.relative_to(stdlib))] = path
    extensions = {'python_extension_' + str(index): path
                  for index, path in enumerate(files.values()) if path.suffix == '.so'}
    return files, extensions, {'interpreter': str(interpreter), 'stdlib': str(stdlib),
                               'version': version, 'version_query': command}
