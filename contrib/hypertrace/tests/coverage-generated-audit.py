#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Attribute declared syscall assembly and libc source aliases without coverage credit."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    out = args.output.resolve()
    if not out.is_relative_to('/usr/obj') or out.exists():
        parser.error('Use a new /usr/obj output directory')
    inventory = json.loads(args.inventory.read_text())
    out.mkdir(parents=True)
    env = os.environ.copy()
    for name in ('MAKEFLAGS', 'MFLAGS', 'MAKEOBJDIR', 'MAKEOBJDIRPREFIX',
                 'CFLAGS', 'CXXFLAGS', 'LDFLAGS'):
        env.pop(name, None)
    rows = []
    declarations = []
    for entry in inventory['configurations']:
        variables = {}
        if entry['target'] in ('lib/libc', 'lib/libsys'):
            # Refuse to reinterpret an inventory after its build recipes changed.
            for name, expected in entry['makefiles'].items():
                path = Path(name)
                if not path.is_file() or digest(path) != expected:
                    raise RuntimeError('Stale inventory Makefile: '+name)
            command = ['make', '-C', str(root/entry['target']), '-m', str(root/'share/mk'),
                'SRCTOP='+str(root), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
                'MACHINE='+entry['machine'], 'MACHINE_ARCH='+entry['arch'],
                'TARGET='+entry['machine'], 'TARGET_ARCH='+entry['arch'],
                'WITH_BHYVE_SNAPSHOT=yes' if entry['snapshot'] else 'WITHOUT_BHYVE_SNAPSHOT=yes']
            names = ('SASM', 'SPSEUDO', '__asm_deps', 'JEMALLOCSRCS',
                     'GDTOASRCS', 'CANCELPOINTS_SRCS')
            for name in names:
                command += ['-V', '${'+name+'}']
            process = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60)
            lines = process.stdout.splitlines()
            if process.returncode or process.stderr.strip() or len(lines) != len(names):
                raise RuntimeError('Cannot evaluate generation declarations: '+process.stderr)
            variables = dict(zip(names, lines))
            dependencies = []
            for name in variables['__asm_deps'].split():
                path = Path(name)
                if not path.is_absolute():
                    path = root/entry['target']/path
                dependencies.append({'path': str(path),
                    'sha256': digest(path) if path.is_file() else None})
            declarations.append({'target': entry['target'], 'arch': entry['arch'],
                'snapshot': entry['snapshot'], 'command': command,
                'variables': variables, 'recipe_inputs': dependencies})
        aliases = {}
        if entry['target'] == 'lib/libc':
            for variable, prefix, source_dir, recipe in (
                ('JEMALLOCSRCS', 'jemalloc_', 'contrib/jemalloc/src',
                 'lib/libc/stdlib/malloc/jemalloc/Makefile.inc'),
                ('GDTOASRCS', 'gdtoa_', 'contrib/gdtoa',
                 'lib/libc/gdtoa/Makefile.inc'),
                ('CANCELPOINTS_SRCS', 'cancelpoints_', 'lib/libc/gen',
                 'lib/libc/gen/Makefile.inc')):
                for name in variables.get(variable, '').split():
                    aliases[prefix+name] = (root/source_dir/name, root/recipe, variable)
            aliases['C99_Exit.c'] = (root/'lib/libc/stdlib/_Exit.c',
                root/'lib/libc/stdlib/Makefile.inc', 'explicit C99_Exit.c rule')
        generated = {name: kind for kind in ('SASM', 'SPSEUDO')
            for name in variables.get(kind, '').split()}
        for item in entry.get('inputs', []):
            if item['path'] is not None:
                continue
            kind = generated.get(item['name']) if item['kind'] == 'SRCS' else None
            alias = aliases.get(item['name']) if item['kind'] == 'SRCS' else None
            lineage = None
            if alias:
                source, recipe, declaration = alias
                if not source.is_file() or not recipe.is_file():
                    raise RuntimeError('Missing source-alias evidence: '+item['name'])
                if str(recipe) not in entry['makefiles']:
                    raise RuntimeError('Source-alias recipe not evaluated: '+str(recipe))
                lineage = {'source': str(source), 'source_sha256': digest(source),
                    'recipe': str(recipe), 'recipe_sha256': digest(recipe),
                    'declaration': declaration}
            rows.append({'target': entry['target'], 'arch': entry['arch'],
                'snapshot': entry['snapshot'], 'input': item,
                'classification': ('declared-syscall-assembly' if kind else
                    'declared-source-alias' if lineage else 'still-unattributed'),
                'source_lineage': lineage,
                'declaration': kind, 'output_verified': False,
                'coverage': 'not-established-by-generation-declaration'})
    report = {'inventory_sha256': digest(args.inventory), 'driver_sha256': digest(Path(__file__)),
        'scope': 'Generator declarations only; no outputs built, no coverage exclusion',
        'counts': dict(Counter(r['classification'] for r in rows)),
        'declarations': declarations, 'inputs': rows}
    (out/'audit.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report['counts']))


if __name__ == '__main__':
    main()
