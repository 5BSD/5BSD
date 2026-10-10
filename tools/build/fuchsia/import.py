#!/usr/bin/env python3.12
"""Reproduce pinned upstream imports into an EMPTY contrib staging directory.

The lock file records URLs and SHA256 values. Local patches are applied only
with --patch. This never overwrites an existing source checkout.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--lock', type=Path, default=Path(__file__).with_name('sources.json'))
p.add_argument('--dest', type=Path, required=True)
p.add_argument('--cache', type=Path, default=Path('/usr/obj/5bsd-contrib-distfiles'))
p.add_argument('--patch', action='store_true')
a = p.parse_args()
dest = a.dest.resolve()
if dest.exists() and any(dest.iterdir()):
    p.error('--dest must be empty (refresh into staging, then review a diff)')
dest.mkdir(parents=True, exist_ok=True)
a.cache.mkdir(parents=True, exist_ok=True)
lock = json.loads(a.lock.read_text())

def tree_digest(path):
    """Gitiles archives change tar timestamps; verify names, modes and contents."""
    entries = []
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            if member.isfile():
                with archive.extractfile(member) as stream:
                    content = hashlib.file_digest(stream, 'sha256').hexdigest()
            elif member.issym() or member.islnk():
                content = member.linkname
            elif member.isdir():
                content = ''
            else:
                raise RuntimeError('Unsupported archive entry: ' + member.name)
            entries.append([member.name, member.type.decode('ascii'), member.mode & 0o777, content])
    return hashlib.sha256(json.dumps(sorted(entries), separators=(',', ':')).encode()).hexdigest()

def verified(path, entry):
    if 'tree_sha256' in entry:
        return tree_digest(path) == entry['tree_sha256']
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest() == entry['sha256']

def fetch(entry):
    target = a.cache / entry['sha256']
    if not target.exists():
        with tempfile.NamedTemporaryFile(dir=a.cache, delete=False) as tmp:
            path = Path(tmp.name)
        try:
            subprocess.run(['curl', '-fLsS', '--retry', '3', '--max-time', '300',
                            '-o', str(path), entry['url']], check=True)
            data = path.read_bytes()
            if entry.get('base64'):
                data = base64.b64decode(data, validate=False)
            path.write_bytes(data)
            if not verified(path, entry):
                raise RuntimeError('Checksum mismatch: ' + entry['url'])
            path.replace(target)
        finally:
            path.unlink(missing_ok=True)
    if not verified(target, entry):
        raise RuntimeError('Corrupt cache file: ' + str(target))
    return target

for entry in lock['sources']:
    path = Path(entry['path'])
    if path.is_absolute() or '..' in path.parts:
        raise RuntimeError('Unsafe destination: ' + str(path))
    source = fetch(entry)
    if entry.get('file'):
        (dest / path).parent.mkdir(parents=True, exist_ok=True)
        (dest / path).write_bytes(source.read_bytes())
    else:
        # Optional include/exclude lists keep or drop those paths and
        # everything under them; the trim is part of the lock, so it
        # reproduces.
        include = [Path(i).parts for i in entry.get('include', [])]
        exclude = [Path(i).parts for i in entry.get('exclude', [])]
        with tarfile.open(source) as archive:
            members = []
            for member in archive.getmembers():
                parts = Path(member.name).parts
                if member.name.startswith('/') or '..' in parts:
                    raise RuntimeError('Unsafe archive path: ' + member.name)
                parts = parts[entry.get('strip_components', 0):]
                if not parts:
                    continue
                if include and not any(parts[:len(i)] == i for i in include):
                    continue
                if any(parts[:len(x)] == x for x in exclude):
                    continue
                member.name = str(path.joinpath(*parts))
                # Gitiles export timestamps vary and may be in the future.
                # Content/modes are verified above; use a stable build mtime.
                member.mtime = 1
                members.append(member)
            archive.extractall(dest, members=members, filter='data')
    print('Imported ' + str(path), flush=True)
for path, data in lock['metadata'].items():
    relative = Path(path)
    if relative.is_absolute() or '..' in relative.parts:
        raise RuntimeError('Unsafe metadata path: ' + path)
    (dest / relative).write_text(json.dumps(data, indent=2) + '\n')
if a.patch:
    for patch in sorted(a.lock.parent.glob('patches/*.patch')):
        subprocess.run(['patch', '-t', '-N', '-F0', '-V', 'none', '-d', str(dest),
                        '-p1', '-i', str(patch.resolve())], check=True)
