#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check BSD tar extraction of a trusted build-produced installation archive.

The private extraction does not apply root ownership. Numeric identities are
archive metadata; this does not qualify privileged installation or pkg lifecycle.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile


def sha(stream):
    return hashlib.file_digest(stream, 'sha256').hexdigest()


def qualify(archive, output, tar):
    archive = archive.resolve(strict=True)
    if output.is_symlink():
        raise ValueError('output must not be a symlink')
    output = output.resolve()
    if output.exists() or not output.is_relative_to('/usr/obj'):
        raise ValueError('fresh output under /usr/obj required')
    output.mkdir()
    root = output / 'extracted'
    root.mkdir()
    with tarfile.open(archive) as source:
        members = source.getmembers()
        names = set()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or str(path) in names:
                raise ValueError('unsafe or duplicate archive path')
            names.add(str(path))
        command = [str(tar), '-xpf', str(archive), '--no-same-owner', '-C', str(root)]
        subprocess.run(command, check=True)
        results = []
        for member in members:
            path = root / member.name
            if member.issym():
                assert path.is_symlink() and os.readlink(path) == member.linkname
            else:
                assert not path.is_symlink()
                assert path.stat().st_mode & 0o7777 == member.mode, member.name
                if member.isdir():
                    assert path.is_dir()
                elif member.islnk():
                    assert path.samefile(root / member.linkname), member.name
                elif member.isfile():
                    with path.open('rb') as actual, source.extractfile(member) as expected:
                        assert sha(actual) == sha(expected), member.name
                else:
                    raise ValueError('unsupported archive object: ' + member.name)
            results.append(dict(path=member.name, type=member.type.decode(), mode=member.mode))
        actual = {'.'} | {str(p.relative_to(root)) for p in root.rglob('*')}
        assert actual == names, (actual - names, names - actual)
    with archive.open('rb') as stream:
        digest = sha(stream)
    receipt = dict(status='passed', archive=str(archive), archive_sha256=digest,
                   command=command, objects=results,
                   limitations=['Ownership not applied; private unprivileged extraction',
                                'Trusted build archive only, not an untrusted archive parser',
                                'No package lifecycle qualification'])
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return root


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--tar', type=Path, required=True)
    a = p.parse_args()
    print(qualify(a.archive, a.output, a.tar))
