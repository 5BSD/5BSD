#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Reconcile one LLVM export with build inputs; never certify whole-system coverage.

Exact paths and source digests are required. Generated inputs and unmapped files
remain visible; matching basenames or a high mapped-subset average is insufficient.
"""
import argparse
import hashlib
import json
from pathlib import Path

METRICS = ('lines', 'branches', 'functions')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def reconcile(inventory, coverage, provenance, root, arch, snapshot):
    if coverage.get('type') != 'llvm.coverage.json.export' or len(coverage.get('data', [])) != 1:
        raise ValueError('Expected one LLVM export dataset; merge profiles before export')
    rows = {}
    for row in coverage['data'][0]['files']:
        path = str(Path(row['filename']).resolve())
        if path in rows:
            raise ValueError('Duplicate coverage path: '+path)
        rows[path] = row
    hashes = {str(Path(p).resolve()): h for p, h in provenance['source_sha256'].items()}
    configurations = [e for e in inventory['configurations']
                      if e['arch'] == arch and e['snapshot'] == snapshot]
    if not configurations:
        raise ValueError('No matching inventory configuration')
    components = []
    for entry in configurations:
        component = {'target': entry['target'], 'inputs': [], 'mapped_subset_metrics': {},
                     'coverage_accepted': False,
                     'reason': 'Seed inventory is not closed; this is a reconciliation report, not qualification'}
        selected = {}
        for item in entry.get('inputs', []):
            # Keep installed artifacts and headers visible, even if they have no
            # executable mapping. Never invent a zero executable denominator.
            result = {'kind': item['kind'], 'name': item['name'], 'path': item['path']}
            if item['path'] is None:
                result['status'] = 'unresolved-or-generated'
            else:
                path = Path(item['path'])
                path = (root/path).resolve() if not path.is_absolute() else path.resolve()
                key = str(path)
                if not path.is_file() or digest(path) != item['sha256']:
                    result['status'] = 'inventory-source-changed'
                elif key not in rows:
                    result['status'] = 'no-executable-mapping-established'
                elif hashes.get(key) != item['sha256']:
                    result['status'] = 'export-source-provenance-unverified'
                else:
                    result['status'] = 'mapped-source-digest-matched'
                    result['metrics'] = rows[key]['summary']
                    selected[key] = rows[key]
            component['inputs'].append(result)
        for metric in METRICS:
            count = sum(r['summary'][metric]['count'] for r in selected.values())
            covered = sum(r['summary'][metric]['covered'] for r in selected.values())
            if not 0 <= covered <= count:
                raise ValueError('Invalid LLVM counters')
            component['mapped_subset_metrics'][metric] = {
                'count': count, 'covered': covered,
                'percent': 100*covered/count if count else None,
                'mapped_subset_meets_97': count > 0 and covered*100 >= count*97}
        component['inventory_status'] = entry['status']
        components.append(component)
    return {'arch': arch, 'snapshot': snapshot, 'components': components,
            'coverage_accepted': False, 'live_qualification': 'deferred',
            'limitations': ['Source digest agreement does not establish build-time source provenance',
                'Header/dependency closure and generated-source attribution remain required',
                'This export does not establish coverage for other binaries or configurations']}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('inventory', type=Path)
    p.add_argument('export', type=Path)
    p.add_argument('provenance', type=Path)
    p.add_argument('output', type=Path)
    p.add_argument('--arch', required=True, choices=('amd64','aarch64','riscv64'))
    p.add_argument('--snapshot', action='store_true')
    args = p.parse_args()
    root = Path(__file__).resolve().parents[3]
    output = args.output.resolve()
    if not output.is_relative_to('/usr/obj') or output.exists():
        p.error('Use a new output file under /usr/obj')
    report = reconcile(json.loads(args.inventory.read_text()),
        json.loads(args.export.read_text()), json.loads(args.provenance.read_text()),
        root, args.arch, args.snapshot)
    report['evidence_sha256'] = {str(f.resolve()): digest(f)
        for f in (args.inventory, args.export, args.provenance, Path(__file__))}
    output.write_text(json.dumps(report, indent=2)+'\n')
    for c in report['components']:
        statuses = {}
        for i in c['inputs']:
            statuses[i['status']] = statuses.get(i['status'], 0)+1
        print(c['target'], json.dumps(statuses))

if __name__ == '__main__':
    main()
