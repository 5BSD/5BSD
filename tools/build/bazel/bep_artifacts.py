# SPDX-License-Identifier: BSD-2-Clause
"""Freeze local default and installation-metadata output files from Bazel's completed BEP graph."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
from urllib.parse import unquote, urlsplit


def snapshot(events_path, destination):
    sets = {}
    targets = []
    with Path(events_path).open() as stream:
        for line in stream:
            event = json.loads(line)
            if 'namedSetOfFiles' in event:
                key = event['id']['namedSet']['id']
                if key in sets and sets[key] != event['namedSetOfFiles']:
                    raise ValueError('conflicting BEP file set: ' + key)
                sets[key] = event['namedSetOfFiles']
            if 'targetCompleted' in event.get('id', {}):
                identity = event['id']['targetCompleted']
                if identity.get('aspect'):
                    continue
                if not event['completed'].get('success'):
                    raise ValueError('unsuccessful target output: ' + identity['label'])
                groups = [g for g in event['completed'].get('outputGroup', []) if g['name'] in ('default', 'metadata', 'directory_metadata')]
                if any(g.get('incomplete') for g in groups):
                    raise ValueError('incomplete captured output group')
                targets.append((identity, [r['id'] for g in groups for r in g.get('fileSets', [])]))
    if not targets:
        raise ValueError('no completed targets in BEP')
    def expand(key, active, visited):
        if key in active:
            raise ValueError('cyclic BEP file sets')
        if key not in sets:
            raise ValueError('missing BEP file set: ' + key)
        if key in visited:
            return
        node = sets[key]
        yield from node.get('files', [])
        for child in node.get('fileSets', []):
            yield from expand(child['id'], active | {key}, visited)
        visited.add(key)
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    blobs = destination / 'files'
    blobs.mkdir(mode=0o700)
    records = []
    seen = {}
    for identity, roots in targets:
        outputs = {}
        visited = set()
        for root in roots:
            for file in expand(root, set(), visited):
                name = '/'.join([*file.get('pathPrefix', []), file['name']])
                relative = PurePosixPath(name)
                if relative.is_absolute() or '..' in relative.parts or not relative.parts:
                    raise ValueError('unsafe BEP output name: ' + name)
                uri = urlsplit(file.get('uri', ''))
                if uri.scheme != 'file' or uri.netloc or uri.query or uri.fragment:
                    raise ValueError('local file URI required for output: ' + name)
                source = Path(unquote(uri.path))
                if not source.is_absolute() or not source.is_file():
                    raise ValueError('regular output file required: ' + str(source))
                expected = file.get('digest')
                if not isinstance(expected, str) or len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
                    raise ValueError('SHA-256 BEP digest required: ' + name)
                size = int(file['length'])
                mode = stat.S_IMODE(source.stat().st_mode)
                # Always verify the source, including repeated/shared artifacts.
                with source.open('rb') as stream:
                    actual = hashlib.file_digest(stream, 'sha256').hexdigest()
                if actual != expected or source.stat().st_size != size:
                    raise ValueError('BEP output changed before capture: ' + name)
                blob = blobs / expected
                if expected not in seen:
                    shutil.copyfile(source, blob)
                    with blob.open('rb') as stream:
                        copied = hashlib.file_digest(stream, 'sha256').hexdigest()
                    if copied != expected or blob.stat().st_size != size:
                        raise ValueError('output changed during capture: ' + name)
                    blob.chmod(0o400)
                    seen[expected] = size
                record = dict(name=name, uri=file['uri'], sha256=expected, size=size, mode=format(mode, '04o'), file='files/' + expected)
                if name in outputs and outputs[name] != record:
                    raise ValueError('conflicting target output: ' + name)
                outputs[name] = record
        records.append(dict(target=identity, outputs=[outputs[k] for k in sorted(outputs)]))
    report = dict(format=1, scope='completed targets, default/metadata/directory_metadata groups, regular files only; excludes runfiles and other output groups', targets=records, unique_files=len(seen), bytes=sum(seen.values()))
    (destination/'manifest.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    manifest_hash = hashlib.sha256((destination/'manifest.json').read_bytes()).hexdigest()
    return dict(manifest='artifacts/manifest.json', sha256=manifest_hash, unique_files=len(seen), bytes=sum(seen.values()))
