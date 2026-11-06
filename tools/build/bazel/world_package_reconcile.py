# SPDX-License-Identifier: BSD-2-Clause
"""Require exact selected metadata coverage before creating world packages."""
import hashlib
import json
from pathlib import Path
import sys


def reconcile(inventory, catalogue):
    if inventory.get('format') != 1 or inventory.get('scope') != 'world-package-inventory':
        raise ValueError('world package inventory format 1 required')
    if catalogue.get('format') != 1 or catalogue.get('scope') != 'world-package-family-set':
        raise ValueError('selected package family catalogue format 1 required')
    payloads, declarations = inventory['packages'], catalogue['packages']
    unknown = sorted(set(payloads) - set(declarations))
    if unknown:
        raise ValueError('world payload lacks selected package metadata: ' + ', '.join(unknown))
    metadata_only = sorted(name for name, declaration in declarations.items() if declaration['metadata_only'])
    for name in metadata_only:
        if name in payloads:
            raise ValueError('metadata-only package has installation claims: ' + name)
    empty = sorted(name for name in declarations if name not in metadata_only and
                   not any(record['type'] != 'dir' for record in payloads.get(name, [])))
    if empty:
        raise ValueError('selected package has no payload: ' + ', '.join(empty))
    return dict(format=1, scope='world-package-metadata-reconciliation', status='passed',
                prefix=catalogue['prefix'], version=catalogue['version'],
                families=sorted(catalogue['families']), packages=sorted(declarations),
                metadata_only=metadata_only, construction=sorted(inventory['construction']),
                summary=dict(families=len(catalogue['families']), packages=len(declarations),
                             payload_packages=len(payloads), metadata_only_packages=len(metadata_only),
                             nondirectory_paths=inventory['summary']['nondirectory_paths']))


def main():
    inventory = Path(sys.argv[1]).read_bytes()
    catalogue = Path(sys.argv[2]).read_bytes()
    selected = json.loads(catalogue)
    result = reconcile(json.loads(inventory), selected)
    result['manifest_sha256'] = {name: hashlib.sha256(Path(declaration['manifest']).read_bytes()).hexdigest()
                                 for name, declaration in selected['packages'].items()}
    result['input_sha256'] = dict(inventory=hashlib.sha256(inventory).hexdigest(),
                                  catalogue=hashlib.sha256(catalogue).hexdigest())
    Path(sys.argv[3]).write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
