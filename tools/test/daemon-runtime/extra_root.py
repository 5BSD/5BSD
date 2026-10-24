# SPDX-License-Identifier: BSD-2-Clause
"""Add explicit fixture data without replacing runner-owned inputs."""
import hashlib
import re
import shutil
import stat
from pathlib import Path


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def stage_extra_root(source, destination, shared_files=None):
    source, destination = Path(source), Path(destination)
    if source.is_symlink() or not source.is_dir():
        raise ValueError('extra fixture root must be a directory, not a link')
    hashes = {}
    shared_files = dict(shared_files or {})
    shared = {}
    entries = sorted(source.rglob('*'))
    # Validate the entire input before copying any of it.
    for path in entries:
        if any(re.fullmatch(r'[A-Za-z0-9_.+\-]+', part) is None
               for part in path.relative_to(source).parts):
            raise ValueError('extra fixture pathname cannot be represented by this METALOG: ' + str(path))
        mode = path.lstat().st_mode
        target = destination / path.relative_to(source)
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError('extra fixture must contain only directories and regular files: ' + str(path))
        relative = str(path.relative_to(source))
        if (relative in shared_files and stat.S_ISREG(mode) and
                target.is_file() and not target.is_symlink()):
            expected = shared_files[relative]
            if any(digest(p) != expected
                   for p in (path, target)):
                raise ValueError('shared fixture digest differs: ' + relative)
            hashes[relative] = shared[relative] = expected
            continue
        if target.is_symlink() or (target.exists() and
                not (stat.S_ISDIR(mode) and target.is_dir())):
            raise ValueError('extra fixture conflicts with staged input: ' + str(target))
        if stat.S_ISREG(mode):
            hashes[str(path.relative_to(source))] = digest(path)
    for path in entries:
        relative = path.relative_to(source)
        target = destination / relative
        if str(relative) in shared:
            if any(digest(p) != shared[str(relative)]
                   for p in (path, target)):
                raise ValueError('shared fixture changed during staging: ' + str(relative))
            continue
        if path.is_dir():
            target.mkdir(exist_ok=True)
        else:
            shutil.copyfile(path, target)
            if any(digest(p) != hashes[str(relative)]
                   for p in (path, target)):
                raise ValueError('extra fixture input changed: ' + str(path))
    return {'source': str(source.resolve()), 'files_sha256': hashes, 'shared_files_sha256': shared}
