#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check the FIDL binding sets that buildworld generates.

Every binding set named by a FIDL_BINDINGS entry in a lib/ or usr.sbin/
Makefile (lib/libfidl/fidl-bindings.mk) is generated twice, into separate
scratch directories, with the same fidlgen-build.py that the build runs; the
two trees must be byte-identical (deterministic output).  Each evolution
test's next schema (a *_next set compiled at bsd:2) must also compile at
bsd:1 to exactly its production schema: same declarations, ordinals and
layouts.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--src', type=Path, default=Path('/usr/src'))
p.add_argument('--obj', type=Path, default=Path('/usr/obj/5bsd-fidl-runtime'))
p.add_argument('--tools', type=Path, default=Path('/usr/obj/5bsd-fidl'),
               help='directory holding fidlc')
p.add_argument('--fidlc', type=Path, help='fidlc to use instead of TOOLS/fidlc')
a = p.parse_args()
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
fidlc = a.fidlc or a.tools / 'fidlc'
# The build's default platform version (FIDL_AVAILABLE in fidl-bindings.mk):
# every production library is @available(platform="bsd", added=1).
AVAILABLE = ['--available', 'bsd:1']
a.obj.mkdir(parents=True, exist_ok=True)


def binding_sets():
    """{name: (schemas, library, flags)} from the tree's Makefiles."""
    sets = {}
    assign = re.compile(r'^FIDL_(SCHEMAS|LIBRARY|FLAGS)\.([A-Za-z0-9_]+)=\s*'
                        r'((?:[^\n]*\\\n)*[^\n]*)', re.M)
    for makefile in sorted([*a.src.glob('lib/**/Makefile'),
                            *a.src.glob('usr.sbin/**/Makefile')]):
        text = makefile.read_text()
        if 'fidl-bindings.mk' not in text:
            continue
        found = {}
        for kind, name, value in assign.findall(text):
            found.setdefault(name, {})[kind] = value.replace('\\\n', ' ').split()
        for name, fields in found.items():
            entry = (tuple(fields['SCHEMAS']), ' '.join(fields['LIBRARY']),
                     tuple(fields.get('FLAGS', ())))
            if sets.setdefault(name, entry) != entry:
                p.exit(1, f'{makefile}: binding set {name} differs from '
                       'another Makefile\'s definition\n')
    return sets


def schema_paths(schemas):
    return [Path(s) if s.startswith('/') else a.src / s for s in schemas]


def generate(schemas, flags, out):
    command = [sys.executable, str(a.src / 'tools/build/fuchsia/fidlgen-build.py'),
               '--fidlc', str(fidlc), '--out', str(out), '--available', AVAILABLE[1],
               *[f'--fidlc-flag={f}' for f in flags],
               *map(str, schema_paths(schemas))]
    subprocess.run(command, check=True)
    return {str(f.relative_to(out)): f.read_bytes()
            for f in out.rglob('*') if f.is_file()}


def semantic(value):
    if isinstance(value, list):
        return [semantic(v) for v in value]
    if isinstance(value, dict):
        return {k: semantic(v) for k, v in value.items()
                if k not in ('location', 'maybe_attributes', 'deprecated',
                             'available', 'platform')}
    return value


def compatible(next_schemas, production, work):
    irs = []
    for tag, schemas, extra in (('v1', next_schemas, AVAILABLE),
                                ('prod', production, AVAILABLE)):
        out = work / (tag + '.json')
        files = []
        for schema in schema_paths(schemas):
            files += ['--files', str(schema)]
        subprocess.run([str(fidlc), '--json', str(out), *extra, *files],
                       check=True)
        irs.append(json.loads(out.read_text()))
    keys = [k for k in irs[1] if k.endswith('_declarations')]
    keys.append('declaration_order')
    return [k for k in keys if semantic(irs[0].get(k)) != semantic(irs[1].get(k))]


sets = binding_sets()
if not sets:
    p.exit(1, 'no FIDL_BINDINGS sets found under ' + str(a.src) + '\n')
failures, files, evolutions = [], 0, 0
with tempfile.TemporaryDirectory(prefix='test-bindings-', dir=a.obj) as temporary:
    work = Path(temporary)
    for name, (schemas, library, flags) in sorted(sets.items()):
        first = generate(schemas, flags, work / name / 'first')
        second = generate(schemas, flags, work / name / 'second')
        if not any(k.startswith(f'fidl/{library}/') for k in first):
            failures.append(f'{name}: no fidl/{library} output')
        failures += [f'{name}/{item}: differs between two generations'
                     for item in sorted(first.keys() | second.keys())
                     if first.get(item) != second.get(item)]
        files += len(first)
        if name.endswith('_next'):
            production = sets.get(name[:-len('_next')])
            if production is None:
                failures.append(f'{name}: no production set {name[:-5]}')
                continue
            check = work / name / 'evolution'
            check.mkdir()
            bad = compatible(schemas, production[0], check)
            if bad:
                failures.append(f'{name}: bsd:1 differs from the production '
                                f'schema in: {bad}')
            evolutions += 1
if failures:
    p.exit(1, '\n'.join(failures) + '\n')
print(f'FIDL bindings: {len(sets)} sets, {files} files generated identically '
      f'twice; {evolutions} next schemas are additive at bsd:1: PASS')
