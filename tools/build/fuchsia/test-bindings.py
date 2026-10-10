#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Regenerate or verify native-test fixtures using the pinned FIDL host tools."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--src', type=Path, default=Path('/usr/src'))
p.add_argument('--obj', type=Path, default=Path('/usr/obj/5bsd-fidl-runtime'))
p.add_argument('--tools', type=Path, default=Path('/usr/obj/5bsd-fidl'))
p.add_argument('--write', action='store_true', help='replace the checked-in fixtures')
a = p.parse_args()
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
a.obj.mkdir(parents=True, exist_ok=True)
projects = [
    ('runtime', a.src/'lib/libfidl/tests', ['zx.fidl', 'runtime.fidl']),
    ('timecmp', a.src/'lib/libtimecmp', ['timecmp.fidl']),
]
with tempfile.TemporaryDirectory(prefix='test-bindings-', dir=a.obj) as temporary:
    def contents(root):
        return {str(f.relative_to(root)): f.read_bytes()
                for f in root.rglob('*') if f.is_file()}
    outputs, differences, count = [], [], 0
    for name, source, schemas in projects:
        work = Path(temporary)/name
        work.mkdir()
        ir, generated, destination = work/'schema.json', work/'generated', source/'generated'
        command = [str(a.tools/'fidlc'), '--json', str(ir)]
        for schema in schemas:
            command += ['--files', str(source/schema)]
        subprocess.run(command, check=True)
        subprocess.run([sys.executable, str(a.src/'tools/build/fuchsia/generate-bsd.py'),
                        '--json', str(ir), '--root', str(generated), '--c',
                        '--fidlgen-cpp', str(a.tools/'fidlgen_cpp')], check=True)
        expected, current = contents(generated), contents(destination)
        differences += [name+'/'+item for item in sorted(expected.keys() | current.keys())
                        if expected.get(item) != current.get(item)]
        count += len(expected)
        outputs.append((generated, destination))
    if differences and not a.write:
        p.exit(1, 'Generated bindings are stale; regenerate with --write:\n' +
               '\n'.join(differences) + '\n')
    if a.write:
        # Generate all projects successfully before replacing owned outputs.
        for generated, destination in outputs:
            if destination.exists():
                shutil.rmtree(destination)
            shutil.copytree(generated, destination)
    print(f'Native runtime/provider bindings: {count} generated files match: PASS')
