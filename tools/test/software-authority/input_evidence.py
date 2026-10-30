"""Record staged VM inputs; this is provenance, not source/build attestation."""
import hashlib
import os
from pathlib import Path
import stat


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def snapshot_inputs(root):
    root = Path(root)
    entries = {}
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode):
            entries[name] = {'type': 'symlink', 'target': os.readlink(path)}
        elif stat.S_ISREG(before.st_mode):
            checksum = digest(path)
            after = path.lstat()
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            if any(getattr(before, field) != getattr(after, field) for field in fields):
                raise ValueError('staged input changed while recording: ' + name)
            entries[name] = {'type': 'file', 'size': after.st_size, 'sha256': checksum}
        elif not stat.S_ISDIR(before.st_mode):
            raise ValueError('unsupported staged input type: ' + name)
    return {'format': 1, 'scope': 'observed staged content; metadata is in METALOG',
            'entries': entries}
