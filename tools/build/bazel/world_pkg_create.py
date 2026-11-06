# SPDX-License-Identifier: BSD-2-Clause
"""Plan and create source-owned pkgbase outputs with package-local payload inputs."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
import tempfile
from pkg_create import create_staged


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def plans(request):
    inventory = json.loads(Path(request['inventory']).read_text())
    catalogue = json.loads(Path(request['catalogue']).read_text())
    gate = json.loads(Path(request['reconciliation']).read_text())
    if gate.get('status') != 'passed' or gate.get('scope') != 'world-package-metadata-reconciliation':
        raise ValueError('passed world reconciliation required')
    if gate['input_sha256'] != dict(inventory=digest(request['inventory']), catalogue=digest(request['catalogue'])):
        raise ValueError('world reconciliation input mismatch')
    if set(request['outputs']) != set(catalogue['packages']) or set(gate['packages']) != set(request['outputs']):
        raise ValueError('exact selected package outputs required')
    records = {}
    owners = {}
    directories = dict(inventory['shared_directories'])
    for name, entries in inventory['packages'].items():
        for record in entries:
            path = record['destination']
            if record['type'] == 'dir':
                directories.setdefault(path, record)
            else:
                if path in records:
                    raise ValueError('duplicate world payload')
                records[path], owners[path] = record, name
    roots = {}
    for path, record in records.items():
        if record['type'] not in ['file', 'hardlink']:
            continue
        target, seen, chain = path, set(), []
        while target not in roots:
            if target in seen:
                raise ValueError('cyclic hardlink')
            seen.add(target)
            current = records.get(target)
            if current is None or current['type'] not in ['file', 'hardlink']:
                raise ValueError('hardlink lacks regular root')
            if current['type'] == 'file':
                roots[target] = target
                break
            chain.append(target)
            target = current['link']
        for link in chain:
            roots[link] = roots[target]
    for name, output in request['outputs'].items():
        declaration = catalogue['packages'][name]
        original = inventory['packages'].get(name, [])
        materialized, inode_groups = [], {}
        for record in original:
            if record['type'] in ['file', 'hardlink']:
                inode_groups.setdefault(roots[record['destination']], []).append(record['destination'])
        canonical = {root: root if root in paths else min(paths) for root, paths in inode_groups.items()}
        cross_links = []
        for record in original:
            selected = dict(record)
            path = record['destination']
            if record['type'] in ['file', 'hardlink']:
                root = roots[path]
                if path == canonical[root]:
                    selected.update(type='file', source=records[root]['source'])
                    selected.pop('link', None)
                else:
                    selected.update(type='hardlink', link=canonical[root])
                    selected.pop('source', None)
                if owners[root] != name:
                    cross_links.append(dict(path=path, original_target=root, target_package=owners[root]))
            materialized.append(selected)
        required = {'/'}
        for record in materialized:
            path = PurePosixPath(record['destination'])
            required.update(str(p) for p in path.parents)
            if record['type'] == 'dir':
                required.add(str(path))
        if not required.issubset(directories):
            raise ValueError('missing complete source directory policy')
        plan = dict(format=1, scope='world-package-plan', package=name,
            metadata_only=declaration['metadata_only'], manifest_sha256=gate['manifest_sha256'][name],
            records=sorted(materialized, key=lambda r: r['destination']),
            directories={p: directories[p] for p in sorted(required)},
            cross_package_hardlinks=cross_links)
        Path(output).write_text(json.dumps(plan, sort_keys=True, indent=2)+'\n')


def package(request):
    plan = json.loads(Path(request['plan']).read_text())
    name = request['package']
    if plan.get('format') != 1 or plan.get('scope') != 'world-package-plan' or plan['package'] != name:
        raise ValueError('exact package plan required')
    if digest(request['manifest']) != plan['manifest_sha256']:
        raise ValueError('generated package manifest differs from reconciliation')
    output = Path(request['output'])
    sources = set(request['sources'])
    trees = [PurePosixPath(t) for t in request['trees']]
    with tempfile.TemporaryDirectory(prefix='world-pkg-', dir=output.parent) as temporary:
        work = Path(temporary)
        stage = work/'root'
        stage.mkdir()
        dirs = {}
        for path, record in sorted(plan['directories'].items(), key=lambda p: len(PurePosixPath(p[0]).parts)):
            normalized = PurePosixPath(path)
            if not path.startswith('/') or '..' in normalized.parts or str(normalized) != path:
                raise ValueError('canonical directory required')
            target = stage/path.lstrip('/')
            target.mkdir(exist_ok=True)
            meta = tarfile.TarInfo(path.lstrip('/') or '.')
            meta.uname, meta.gname, meta.mode = record['owner'], record['group'], int(record['mode'], 8)
            if record.get('flags') not in (None, '', 'none'):
                meta.pax_headers['SCHILY.fflags'] = record['flags']
            dirs[path] = meta
        owned = set()
        order = dict(dir=0, file=1, hardlink=2, symlink=3)
        for record in sorted(plan['records'], key=lambda r: (order[r['type']], r['destination'])):
            path = record['destination']
            if not path.startswith('/') or str(PurePosixPath(path)) != path or '..' in PurePosixPath(path).parts:
                raise ValueError('canonical payload required')
            target = stage/path.lstrip('/')
            if record['type'] == 'dir':
                owned.add(path)
                continue
            if record['type'] == 'file':
                source = record['source']
                canonical = PurePosixPath(source)
                if '..' in canonical.parts or str(canonical) != source or canonical.is_absolute():
                    raise ValueError('canonical declared source required')
                if source not in sources and not any(canonical.is_relative_to(tree) for tree in trees):
                    raise ValueError('payload source is not a declared package input')
                shutil.copyfile(source, target)
                target.chmod(int(record['mode'], 8))
                os.utime(target, (request['epoch'], request['epoch']))
            elif record['type'] == 'hardlink':
                os.link(stage/record['link'].lstrip('/'), target)
            else:
                os.symlink(record['link'], target)
                os.utime(target, (request['epoch'], request['epoch']), follow_symlinks=False)
        for path, meta in sorted(dirs.items(), key=lambda p: len(PurePosixPath(p[0]).parts), reverse=True):
            target = stage/path.lstrip('/')
            target.chmod(meta.mode)
            os.utime(target, (request['epoch'], request['epoch']))
        packaged = dict(request, packages={name: plan['records']},
            metadata_only=[name] if plan['metadata_only'] else [], outputs={name: str(output)},
            manifests={name: request['manifest']})
        try:
            create_staged(packaged, stage, dirs, {name: owned}, work)
        finally:
            # Target directory permissions belong in pkg metadata. Restore access
            # only inside this private scratch tree so readonly directories clean up.
            for path in sorted(dirs, key=lambda p: len(PurePosixPath(p).parts)):
                (stage/path.lstrip('/')).chmod(0o700)


def index(request):
    entries = []
    for path in request['indexes']:
        value = json.loads(Path(path).read_text())
        if value.get('format') != 1 or len(value['packages']) != 1:
            raise ValueError('one package per declared action index required')
        entries.extend(value['packages'])
    if len(entries) != len({r['name'] for r in entries}):
        raise ValueError('duplicate output package name')
    Path(request['output']).write_text(json.dumps(dict(format=1, packages=sorted(entries, key=lambda r: r['name'])), sort_keys=True, indent=2)+'\n')


if __name__ == '__main__':
    {'plans': plans, 'package': package, 'index': index}[sys.argv[1]](json.loads(Path(sys.argv[2]).read_text()))
