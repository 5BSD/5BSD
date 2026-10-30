#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check actual Bazel execution evidence for the declared libmd archive variants.

Inputs are logs from fresh builds (not cached executions) of fastbuild, dbg and
opt plus a private semantic source mutation; this verifier does not run Bazel.
"""
import argparse
import json
from pathlib import Path

from execution_log import objects


def verify(log, plan):
    rows = [row for row in objects(log) if row.get("mnemonic") in ("BSDLibmdArchive", "CppCompile")]
    archives = [r for r in rows if r['mnemonic'] == 'BSDLibmdArchive']
    assert len(archives) == 2, 'both archive actions required'
    for row in archives:
        argv = row['commandArgs']
        pic = argv[2].endswith('.pic.a')
        assert argv[1] == 'rcsD'
        expected = [Path(s['path']).stem + ('.pic.o' if pic else '.o') for s in plan['sources']]
        assert [Path(p).name for p in argv[3:]] == expected, 'archive object order/membership'
        inputs = {i['path'] for i in row['inputs']}
        assert set(argv[3:]) <= inputs, 'undeclared object input'
        assert argv[0] in inputs, 'undeclared archiver'
        assert {'name': 'LC_ALL', 'value': 'C'} in row['environmentVariables']
        assert row['exitCode'] == 0
        for obj in argv[3:]:
            compiles = [r for r in rows if obj in r.get('listedOutputs', [])]
            assert len(compiles) == 1, 'object needs exactly one compile action'
            flags = compiles[0]['commandArgs']
            assert ('-fPIC' in flags) == pic and ('-DPIC' in flags) == pic
            assert all(f in flags for f in plan['rewritten_cflags'])
    return {'archives': len(archives), 'objects_per_archive': len(plan['sources'])}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    results = {mode: verify(args.evidence / (mode + '.execution.json'), plan)
               for mode in ['fastbuild', 'dbg', 'opt', 'force-pic-fresh']}
    assert list(objects(args.evidence / 'warm.execution.json')) == [], 'warm build reran actions'
    changed = list(objects(args.evidence / 'source-change.execution.json'))
    assert len([r for r in changed if r['mnemonic'] == 'BSDLibmdArchive']) == 2
    assert len([r for r in changed if r['mnemonic'] == 'CppCompile']) == 2
    assert all('md4c.c' in ' '.join(r['commandArgs']) for r in changed if r['mnemonic'] == 'CppCompile')
    print(json.dumps({'passed': True, 'modes': results, 'semantic_source_change_recompiled_both_variants': True}, indent=2))

if __name__ == '__main__':
    main()
