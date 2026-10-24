#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Plan implicit pkg parent directories for the disposable builder fixture only."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def derive(inventory, initial, policy, generation):
    if (set(policy) != {'format', 'scope', 'engine', 'defaults', 'references'} or
            policy['format'] != 1 or policy['scope'] != 'ordinary-pkg-implicit-parents' or
            policy['engine'] != {'name': 'pkg', 'upstream_version': '2.8.4'} or
            policy['defaults'] != {'type': 'directory', 'uid': 0, 'gid': 0,
                                   'mode': 0o755, 'flags_set': 0} or
            not isinstance(policy['references'], list) or not policy['references'] or
            any(not isinstance(x, str) or not x.strip() for x in policy['references'])):
        raise ValueError('unsupported explicit pkg parent policy')
    engines = [p for p in inventory['packages'] if p['name'] == policy['engine']['name']]
    if len(engines) != 1 or engines[0]['version'].split('_')[0] != policy['engine']['upstream_version']:
        raise ValueError('inventory pkg version differs from parent policy')
    packaged = generation.expected_objects(inventory, {'format': 1, 'entries': {}})
    expected = generation.expected_objects(inventory, initial)
    if '/' not in initial['entries']:
        raise ValueError('explicit initial root directory required')
    for name, item in initial['entries'].items():
        if item['type'] != 'directory' or item['replaces'] or name in packaged:
            raise ValueError('initial layout must contain only non-replacing directories: ' + name)
    missing = set()
    for name in expected:
        for parent in Path(name).parents:
            if str(parent) not in expected:
                missing.add(str(parent))
    result = copy.deepcopy(initial)
    for name in sorted(missing):
        result['entries'][name] = dict(policy['defaults'], replaces=[],
            source='ordinary pkg 2.8.4 implicit parent directory policy; derived from selected inventory')
    generation.expected_objects(inventory, result)
    return result, sorted(missing)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inventory', 'initial', 'policy', 'output', 'receipt'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--backend', type=Path,
                        default=Path(__file__).resolve().parents[2] / 'build/capimage')
    args = parser.parse_args()
    inputs = [args.inventory, args.initial, args.policy, Path(__file__),
              *sorted(args.backend.glob('*.py'))]
    identities = {str(p.resolve(strict=True)): digest(p.read_bytes()) for p in inputs}
    outputs = [args.output, args.receipt]
    if (len({str(p.resolve()) for p in outputs}) != 2 or
            any(p.exists() or p.is_symlink() or str(p.resolve()) in identities for p in outputs)):
        raise ValueError('outputs must be distinct new files, separate from inputs')
    spec = importlib.util.spec_from_file_location('generation', args.backend / 'generation_check.py')
    generation = importlib.util.module_from_spec(spec); spec.loader.exec_module(generation)
    layout, added = derive(read_json(args.inventory), read_json(args.initial),
                           read_json(args.policy), generation)
    encoded = (json.dumps(layout, indent=2, sort_keys=True) + '\n').encode()
    if any(digest(Path(p).read_bytes()) != value for p, value in identities.items()):
        raise ValueError('planning inputs changed')
    receipt = {'format': 1, 'scope': 'disposable-builder-layout-planning',
               'result': 'PASS', 'inputs_sha256': identities,
               'layout_sha256': digest(encoded), 'added_directories': added,
               'package_ownership_assigned': False, 'installation_tested': False}
    with args.output.open('xb') as stream:
        stream.write(encoded)
    with args.receipt.open('x') as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True); stream.write('\n')
    print(json.dumps({'result': 'PASS', 'added_directories': len(added),
                      'layout_sha256': receipt['layout_sha256']}))


if __name__ == '__main__':
    main()
