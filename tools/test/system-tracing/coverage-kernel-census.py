#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Collect tracing macro evidence, not semantic coverage or live availability."""
import argparse
import collections
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, default=Path('/usr/src'))
    parser.add_argument('--output', type=Path, default=Path(
        '/usr/obj/5bsd-dtrace-kernel-breadth-validation/kernel-census.json'))
    args = parser.parse_args()
    roots = ['kern', 'vm', 'net', 'netinet', 'netinet6', 'netpfil',
             'netipsec', 'netgraph', 'cam', 'geom', 'fs', 'ufs',
             'security', 'compat', 'dev', 'cddl', 'contrib',
             'amd64', 'arm64', 'riscv', 'x86', 'sys']
    paths = subprocess.check_output(['rg', '--files', *['sys/' + r for r in roots]],
                                    cwd=args.src, text=True).splitlines()
    calls = re.compile(r'\b(?:SDT_PROBE\d*|DTRACE_PROBE\d*|'
                       r'(?:IP|TCP|UDP|UDPLITE|SCTP|CAM|MIB_SDT|LIN_SDT|'
                       r'USB_TRANSFER)_PROBE\d*)\s*\(')
    groups = collections.defaultdict(lambda: dict(files=0, evidence=[]))
    for name in sorted(paths):
        path = Path(name)
        if path.suffix not in ('.c', '.h', '.S'):
            continue
        parts = path.parts
        group = '/'.join(parts[:3] if parts[1] in
                         ('dev', 'fs', 'compat', 'security', 'geom') else parts[:2])
        record = groups[group]
        record['files'] += 1
        content = (args.src / path).read_text(errors='replace')
        # Avoid counting comments as call sites; retain line numbering.
        content = re.sub(r'/\*.*?\*/', lambda m: '\n' * m[0].count('\n'),
                         content, flags=re.S)
        hits = [dict(line=i, macro=m[0].split('(')[0].strip())
                for i, line in enumerate(content.splitlines(), 1)
                if not line.lstrip().startswith('#')
                for m in calls.finditer(line)]
        if hits:
            record['evidence'].append(dict(source=name, calls=hits))
    result = dict(method='Known macro calls and header expansions; not coverage. '
                  'Dynamic providers, unknown wrappers and build options require review.',
                  groups=dict(sorted(groups.items())))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(sum(g['files'] for g in groups.values()), 'source/header files;',
          len(groups), 'groups;', sum(len(g['evidence']) for g in groups.values()),
          'files with known macro evidence')


if __name__ == '__main__':
    main()
