#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Describe selected package inventory for review, without assigning authority.

This report does not authenticate archives, observe runtime accesses, reconcile
an installed tree, or establish functional coverage. Every object needs policy
review. Inputs are the inventory emitted by the maintained build backend.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def backend():
    path = Path(__file__).with_name('package_inventory.py')
    spec = importlib.util.spec_from_file_location('package_inventory', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def state_inventory_review(paths, objects, outputs):
    """Expose lexical overlaps for policy review; never resolve or grant paths.

    A directory entry is inventory, not authority over its descendants. Generated
    outputs are declarations, not evidence that the output exists or is mutable.
    """
    result = {}
    for path in sorted(paths):
        ancestors = set('/'.join(path.split('/')[:n])
            for n in range(2, len(path.split('/'))))
        prefix = path + '/'
        result[path] = {
            'policy_review': 'required',
            'filesystem_resolution_verified': False,
            'exact_package_object': path if path in objects else None,
            'non_directory_package_ancestors': sorted(p for p in ancestors
                if p in objects and objects[p]['metadata']['type'] != 'directory'),
            'contained_package_objects': sorted(p for p in objects if p.startswith(prefix)),
            'generator_overlaps': {p: ('exact' if p == path else
                'ancestor' if p in ancestors else 'descendant') for p in sorted(outputs)
                if p == path or p in ancestors or p.startswith(prefix)}}
    return result


def report(inventory, helpers):
    if (inventory.get('format') != 1 or
            inventory.get('scope') != 'package-payload-inventory' or
            not isinstance(inventory.get('packages'), list) or not inventory['packages']):
        raise ValueError('requires a nonempty package payload inventory')
    objects, packages = {}, {}
    for package in inventory['packages']:
        name = package['name']
        if name in packages:
            raise ValueError('duplicate package identity')
        packages[name] = {'version': package['version'], 'archive_sha256': package['archive_sha256']}
        entries = dict(package['entries'])
        for path, item in helpers.package_directories(package).items():
            entries[path] = helpers.merge_directory(path, entries.get(path, {'type': 'directory'}), item)
        for path, item in entries.items():
            if helpers.canonical_path(path) != path:
                raise ValueError('noncanonical inventory path')
            if item.get('type') not in ('directory', 'file', 'hardlink', 'symlink'):
                raise ValueError('unsupported inventory object type')
            if path in objects:
                row = objects[path]
                row['metadata'] = helpers.merge_directory(path, row['metadata'], item)
                row['owners'].append(name)
            else:
                objects[path] = {'metadata': dict(item), 'owners': [name],
                    'configuration': False, 'policy_review': 'required'}
        for path in package['config']:
            if path not in entries or entries[path]['type'] != 'file':
                raise ValueError('configuration lacks regular package payload')
            objects[path]['configuration'] = True
    for path, row in objects.items():
        row['owners'].sort()
        item = row['metadata']
        row['link_review_required'] = item['type'] in ('symlink', 'hardlink')
        target, seen = path, set()
        while objects[target]['metadata']['type'] == 'hardlink':
            if target in seen:
                raise ValueError('cyclic hardlink')
            seen.add(target)
            target = objects[target]['metadata']['target']
            if target not in objects:
                raise ValueError('missing hardlink target')
        resolved = objects[target]['metadata']
        if item['type'] == 'hardlink' and resolved['type'] != 'file':
            raise ValueError('hardlink lacks regular target')
        row['executable_candidate'] = resolved['type'] == 'file' and bool(resolved['mode'] & 0o111)
        if item['type'] == 'hardlink':
            row['payload_path'] = target
    state = helpers.state_requirements(inventory['packages'])
    # Both paths are candidates until completed-filesystem reconciliation
    # selects the mapping or fallback. Neither declaration grants authority.
    review_paths = set(state['path_review'])
    review_paths.update(item['directory_mapping'] for item in state['requirements']
                        if 'directory_mapping' in item)
    consumers = {}
    for requirement in state['requirements']:
        key = (requirement['package'], requirement['program'])
        consumers.setdefault(key, []).append(requirement['name'])
    # Visit object ownership once; a full pkgbase inventory contains hundreds
    # of packages and tens of thousands of objects. Avoid rescanning the whole
    # inventory for each package. Keep exact-path (including alias) review.
    candidates_by_package = {name: {} for name in packages}
    for path, row in objects.items():
        if not row['executable_candidate']:
            continue
        for name in row['owners']:
            declarations = sorted(consumers.get((name, path), []))
            candidates_by_package[name][path] = {
                'declared_requirements': declarations,
                'declaration_status': 'present' if declarations else 'missing',
                'runtime_paths_complete': False,
                'functional_coverage_verified': False,
                'policy_review': 'required'}
    for name, package in packages.items():
        candidates = candidates_by_package[name]
        package['state_review'] = {
            'executable_candidates': dict(sorted(candidates.items())),
            'candidates_without_declarations': sorted(path for path, row in
                candidates.items() if row['declaration_status'] == 'missing')}
    outputs = {}
    for action in inventory['construction']['actions']:
        for path, metadata in action['outputs'].items():
            if helpers.canonical_path(path) != path or path in outputs:
                raise ValueError('noncanonical or duplicate generator output')
            outputs[path] = {'package': action['package'], 'action': action['name'],
                'metadata': metadata, 'policy_review': 'required', 'execution_verified': False}
    return {'format': 1, 'scope': 'selected-package-review-inventory',
        'authentication_verified': False, 'filesystem_reconciled': False,
        'runtime_paths_complete': False, 'functional_coverage_verified': False,
        'policy_assigned': False,
        'state_requirements': state,
        'state_inventory_review': state_inventory_review(review_paths, objects, outputs),
        'counts': {'packages': len(packages), 'package_objects': len(objects),
            'configuration_paths': sum(r['configuration'] for r in objects.values()),
            'executable_candidates': sum(r['executable_candidate'] for r in objects.values()),
            'links_requiring_review': sum(r['link_review_required'] for r in objects.values()),
            'declared_generator_outputs': len(outputs)},
        'packages': dict(sorted(packages.items())), 'objects': dict(sorted(objects.items())),
        'declared_generator_outputs': dict(sorted(outputs.items()))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    helpers = backend()
    raw = args.inventory.read_bytes()
    inventory = json.loads(raw, object_pairs_hook=helpers.unique_object,
        parse_constant=helpers.invalid_constant)
    result = report(inventory, helpers)
    result['inventory_sha256'] = hashlib.sha256(raw).hexdigest()
    with args.output.open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps(result['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
