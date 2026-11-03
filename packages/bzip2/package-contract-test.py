#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inspect produced packages, their ownership and their complete payloads on the host."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inspect(index, layout, archive, pkg, tar, work):
    layout = json.loads(layout.read_text())
    index_data = json.loads(index.read_text())
    require(index_data['format'] == 1 and layout['format'] == 1, 'unsupported metadata')
    expected = layout['packages']
    require(set(expected) == {'bzip2', 'bzip2-dbg', 'bzip2-dev', 'bzip2-lib'}, 'unexpected family partition')
    rows = index_data['packages']
    require(len(rows) == 4 and len({r['name'] for r in rows}) == 4, 'package output count')
    with tarfile.open(archive) as source:
        members = {'/' + m.name.rstrip('/'): m for m in source.getmembers() if m.name != '.'}
        seen, versions, abis = set(), set(), set()
        report = []
        for row in rows:
            require(Path(row['name']).name == row['name'], 'unsafe package index')
            path = index.parent / row['name']
            require(hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256'], 'package index digest')
            manifest = json.loads(subprocess.check_output([tar, '-xOf', path, '+MANIFEST']))
            name = manifest['name'].removeprefix('5BSD-')
            require(name in expected and name not in seen, 'duplicate or unowned package')
            seen.add(name)
            versions.add(manifest['version'])
            abis.add(manifest['abi'])
            records = {r['destination']: r for r in expected[name]}
            files = {p: r for p, r in records.items() if r['type'] != 'dir'}
            require(set(manifest['files']) == set(files), 'package file partition differs')
            dependencies = set(manifest.get('deps', {}))
            require(dependencies == {'5BSD-' + d for d in layout['dependencies'].get(name, [])}, 'package dependencies differ')
            sets = {'bzip2-dbg': 'minimal-dbg,minimal-jail-dbg', 'bzip2-dev': 'devel'}.get(name, 'minimal,minimal-jail')
            require(manifest['annotations']['set'] == sets, 'package set annotation')
            for p, record in files.items():
                meta = manifest['files'][p]
                require((meta['uname'], meta['gname'], int(meta['perm'], 8)) ==
                        (record['owner'], record['group'], int(record['mode'], 8)), 'file ownership/mode differs: ' + p)
                require(not record.get('flags'), 'this family requires no file flags')
            directories = manifest['directories']
            for p, meta in directories.items():
                original = members[p]
                require((meta['uname'], meta['gname'], int(meta['perm'], 8)) ==
                        (original.uname, original.gname, original.mode), 'directory ownership/mode differs: ' + p)
            for p, r in records.items():
                if r['type'] == 'dir':
                    require(p in directories, 'explicit directory ownership missing')
            # Validate all archive names before extraction, including metadata.
            names = subprocess.check_output([tar, '-tf', path], text=True).splitlines()
            require(len(names) == len(set(names)), 'duplicate archive names')
            wanted = set(files) | {p + '/' for p in directories} | {'+MANIFEST', '+COMPACT_MANIFEST'}
            require(set(names) == wanted, 'archive inventory differs from manifest')
            require(all('..' not in PurePosixPath(n).parts for n in names), 'archive traversal')
            directory = work / name
            directory.mkdir()
            subprocess.run([tar, '-xf', path, '--no-same-owner', '-C', directory], check=True, capture_output=True)
            for p, record in files.items():
                actual = directory / p.lstrip('/')
                original = members[p]
                kind = record['type']
                if kind == 'symlink':
                    require(actual.is_symlink() and os.readlink(actual) == record['link'], 'symlink differs')
                else:
                    require(not actual.is_symlink() and actual.is_file(), 'regular payload expected')
                    require(actual.read_bytes() == source.extractfile(original).read(), 'package payload bytes differ: ' + p)
                    if kind == 'hardlink':
                        target = directory / record['link'].lstrip('/')
                        require(actual.stat().st_ino == target.stat().st_ino, 'package hardlink identity differs')
            # Ask the actual pkg reader to validate each complete package too.
            queried = subprocess.check_output([pkg, 'query', '-F', path, '%n|%v|%q'], text=True).strip()
            require(queried == '|'.join((manifest['name'], manifest['version'], manifest['abi'])), 'pkg query disagrees with manifest')
            report.append({'package': name, 'sha256': row['sha256'], 'files': len(files), 'directories': len(directories)})
    require(seen == set(expected) and len(versions) == 1 and len(abis) == 1, 'family version/ABI inconsistency')
    return {'status': 'passed', 'packages': report, 'abi': abis.pop(), 'version': versions.pop(),
            'scope': 'host inspection of declared package artifacts; no installation or target execution'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('index', 'layout', 'archive', 'pkg', 'tar'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temporary:
        report = inspect(*(getattr(args, n).resolve(strict=True) for n in ('index', 'layout', 'archive', 'pkg', 'tar')), Path(temporary))
    (Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']) / 'packages.json').write_text(json.dumps(report, indent=2) + '\n')
    print('four package inventories, ownership, dependencies, payload bytes and link identities: passed')
