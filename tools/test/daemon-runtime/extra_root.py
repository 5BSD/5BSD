# SPDX-License-Identifier: BSD-2-Clause
"""Add explicit fixture data without replacing runner-owned inputs."""
import hashlib
import os
import posixpath
import shutil
import stat
from pathlib import Path


def mtree_escape(value):
    safe = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._+-@"
    return ''.join(chr(byte) if byte in safe else '\\%03o' % byte
                   for byte in str(value).encode('utf-8'))


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def metalog_component(value):
    """Printable punctuation is escaped by mtree_escape, not a pathname ban."""
    return bool(value) and value not in ('.', '..') and all(
        char.isprintable() and not char.isspace() for char in value)


def stage_extra_root(source, destination, shared_files=None):
    source, destination = Path(source), Path(destination)
    if source.is_symlink() or not source.is_dir():
        raise ValueError('extra fixture root must be a directory, not a link')
    hashes = {}
    symlinks = {}
    file_modes = {}
    inode_groups = {}
    source_inodes = {}
    shared_files = dict(shared_files or {})
    shared = {}
    entries = sorted(source.rglob('*'))
    # Validate the entire input before copying any of it.
    for path in entries:
        if any(not metalog_component(part)
               for part in path.relative_to(source).parts):
            raise ValueError('extra fixture pathname cannot be represented by this METALOG: ' + str(path))
        mode = path.lstat().st_mode
        target = destination / path.relative_to(source)
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
            raise ValueError('extra fixture must contain only directories and regular files: ' + str(path))
        relative = str(path.relative_to(source))
        if stat.S_ISREG(mode):
            info = path.stat()
            identity = (info.st_dev, info.st_ino)
            source_inodes[relative] = identity
            inode_groups.setdefault(identity, []).append(relative)
        if (relative in shared_files and stat.S_ISREG(mode) and
                target.is_file() and not target.is_symlink()):
            expected = shared_files[relative]
            if any(digest(p) != expected
                   for p in (path, target)):
                raise ValueError('shared fixture digest differs: ' + relative)
            hashes[relative] = shared[relative] = expected
            file_modes[relative] = stat.S_IMODE(target.stat().st_mode)
            continue
        if target.is_symlink() or (target.exists() and
                not (stat.S_ISDIR(mode) and target.is_dir())):
            raise ValueError('extra fixture conflicts with staged input: ' + str(target))
        if stat.S_ISLNK(mode):
            link = str(path.readlink())
            normalized = posixpath.normpath(posixpath.join(posixpath.dirname(relative), link))
            if (link.startswith('/') or normalized == '..' or normalized.startswith('../') or
                    any(part not in ('.', '..') and not metalog_component(part) for part in link.split('/'))):
                raise ValueError('extra fixture symlink escapes tree or is unsafe: ' + relative)
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise ValueError('extra fixture symlink is dangling or cyclic: ' + relative) from error
            if not resolved.is_relative_to(source.resolve()) or not resolved.is_file():
                raise ValueError('extra fixture symlink must resolve to an internal regular file: ' + relative)
            symlinks[relative] = link
        if stat.S_ISREG(mode):
            hashes[relative] = digest(path)
            file_modes[relative] = stat.S_IMODE(mode)
    hardlinks = {}
    for members in inode_groups.values():
        anchors = [name for name in members if name in shared]
        anchor = anchors[0] if anchors else members[0]
        if anchors:
            info = (destination / anchor).stat()
            for name in anchors:
                other = (destination / name).stat()
                if (info.st_dev, info.st_ino) != (other.st_dev, other.st_ino):
                    raise ValueError('shared fixture hard links have different inodes: ' + name)
            for name in members:
                if file_modes[name] != stat.S_IMODE(info.st_mode):
                    raise ValueError('shared fixture hard link mode differs: ' + name)
        hardlinks.update({name: anchor for name in members if name != anchor})
    # Copy canonical files first; aliases may sort before a shared anchor.
    for path in entries:
        relative = path.relative_to(source)
        target = destination / relative
        if str(relative) in shared:
            if any(digest(p) != shared[str(relative)]
                   for p in (path, target)):
                raise ValueError('shared fixture changed during staging: ' + str(relative))
            continue
        if str(relative) in symlinks:
            if not path.is_symlink() or str(path.readlink()) != symlinks[str(relative)]:
                raise ValueError('extra fixture symlink changed during staging: ' + str(relative))
            target.symlink_to(symlinks[str(relative)])
        elif path.is_dir():
            target.mkdir(exist_ok=True)
        else:
            info = path.stat()
            if (info.st_dev, info.st_ino) != source_inodes[str(relative)]:
                raise ValueError('extra fixture inode changed during staging: ' + str(relative))
            if str(relative) in hardlinks:
                continue
            shutil.copyfile(path, target)
            if stat.S_IMODE(path.stat().st_mode) != file_modes[str(relative)]:
                raise ValueError('extra fixture mode changed during staging: ' + str(relative))
            target.chmod(file_modes[str(relative)])
            if any(digest(p) != hashes[str(relative)]
                   for p in (path, target)):
                raise ValueError('extra fixture input changed: ' + str(path))
    for relative, anchor in hardlinks.items():
        path = source / relative
        info = path.stat()
        if ((info.st_dev, info.st_ino) != source_inodes[relative] or
                stat.S_IMODE(info.st_mode) != file_modes[relative] or
                digest(path) != hashes[relative]):
            raise ValueError('extra fixture hard link changed during staging: ' + relative)
        if relative not in shared:
            os.link(destination / anchor, destination / relative)
        if digest(destination / relative) != hashes[relative]:
            raise ValueError('extra fixture hard link contents differ: ' + relative)
    return {'hardlinks': hardlinks, 'source': str(source.resolve()), 'files_sha256': hashes, 'shared_files_sha256': shared, 'file_modes': file_modes, 'symlinks': symlinks}
