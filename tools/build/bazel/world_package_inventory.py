# SPDX-License-Identifier: BSD-2-Clause
"""Partition every declared world installation record without reading host state."""
import json
from pathlib import Path, PurePosixPath
import sys


def package(record, suffixes):
    tags = record['tags']
    bases = [tag[8:] for tag in tags if tag.startswith('package=')]
    if len(bases) != 1 or not bases[0] or len(tags) != len(set(tags)):
        raise ValueError('one package tag and no duplicate tags required: ' + record['destination'])
    if any(tag not in suffixes + ['config'] and not tag.startswith('package=') for tag in tags):
        raise ValueError('unmodeled package tags: ' + record['destination'])
    if 'config' in tags and record['type'] != 'file':
        raise ValueError('configuration claim must be a regular file')
    return bases[0] + ''.join('-' + suffix for suffix in suffixes if suffix in tags)


def directory_claim(record):
    result = dict(record)
    result['flags'] = record.get('flags', '') or 'none'
    result['mode'] = format(int(record['mode'], 8), '04o')
    result['tags'] = sorted(record['tags'])
    return result


def inventory(records, declarations, suffixes):
    if len(suffixes) != len(set(suffixes)):
        raise ValueError('duplicate package suffix')
    construction = {}
    for record in declarations:
        path = record['destination']
        if record['type'] != 'file' or record['tags'] or path in construction:
            raise ValueError('construction declarations must name distinct untagged regular files: ' + path)
        construction[path] = record
    packages, shared, directories, payloads, owners, observed, claims = {}, {}, {}, {}, {}, {}, {}
    occurrences = 0
    for record in records:
        path = record['destination']
        if not path.startswith('/') or str(PurePosixPath(path)) != path or '..' in PurePosixPath(path).parts:
            raise ValueError('noncanonical world destination: ' + path)
        kind = record['type']
        if kind not in ['file', 'dir', 'symlink', 'hardlink']:
            raise ValueError('unsupported world object: ' + path)
        if kind == 'dir':
            occurrences += 1
            physical = (record['owner'], record['group'], int(record['mode'], 8), record.get('flags', '') or 'none')
            if path in payloads or (path in directories and directories[path] != physical):
                raise ValueError('conflicting world directory: ' + path)
            directories[path] = physical
            if not record['tags']:
                shared[path] = record
                continue
        else:
            if path in payloads or path in directories:
                raise ValueError('duplicate world payload destination: ' + path)
            payloads[path] = record
            if not record['tags']:
                if construction.get(path) != record:
                    raise ValueError('untagged world file lacks its exact construction declaration: ' + path)
                observed[path] = record
                continue
        name = package(record, suffixes)
        if path in construction:
            raise ValueError('construction file also belongs to a package: ' + path)
        key = (name, path)
        if key in claims:
            if kind != 'dir' or directory_claim(record) != directory_claim(claims[key]):
                raise ValueError('conflicting package claim: ' + name + ': ' + path)
            continue
        claims[key] = record
        packages.setdefault(name, []).append(record)
        if kind != 'dir':
            owners[path] = name
    if set(construction) != set(observed):
        raise ValueError('construction declarations do not match selected world outputs')
    cross_package_hardlinks = {}
    for path, record in payloads.items():
        if record['type'] != 'hardlink':
            continue
        visited, target = set(), path
        while target in payloads and payloads[target]['type'] == 'hardlink':
            if target in visited:
                raise ValueError('cyclic world hardlink: ' + path)
            visited.add(target)
            target = payloads[target]['link']
        if target not in payloads or payloads[target]['type'] != 'file' or target not in owners:
            raise ValueError('world hardlink has no packaged regular target: ' + path)
        original = payloads[target]
        if any(record[key] != original[key] for key in ['owner', 'group', 'mode']) or (record.get('flags', '') or 'none') != (original.get('flags', '') or 'none'):
            raise ValueError('world hardlink inode metadata differs: ' + path)
        if owners[path] != owners[target]:
            cross_package_hardlinks[path] = dict(package=owners[path], target=target, target_package=owners[target])
    return dict(format=1, scope='world-package-inventory', packages=packages,
        construction=observed, shared_directories=shared, suffix_tags=suffixes,
        cross_package_hardlinks=cross_package_hardlinks,
        summary=dict(nondirectory_paths=len(payloads), directory_paths=len(directories),
            directory_record_occurrences=occurrences, package_claims=len(claims)))


def main():
    request = json.loads(Path(sys.argv[1]).read_text())
    if request['format'] != 1:
        raise ValueError('world inventory request format 1 required')
    records = list(request['records'])
    trees = []
    for tree in request['trees']:
        metadata = json.loads(Path(tree['metadata']).read_text())
        records.extend(metadata['records'])
        trees.append(dict(prefix=tree['prefix'], metadata=tree['metadata'], records=len(metadata['records'])))
    for path in request['directory_metadata']:
        policy = json.loads(Path(path).read_text())
        records.extend(policy['directories'])
        # Physical parent policy does not itself grant package ownership.
        records.extend(dict(record, tags=[]) for record in policy['physical_directories'])
    result = inventory(records, request['construction'], request['suffix_tags'])
    result['expanded_trees'] = trees
    Path(sys.argv[2]).write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
