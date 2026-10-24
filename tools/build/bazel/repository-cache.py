#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Export a pinned Bazel distribution's repository cache without executing it."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import zipfile

PREFIX = 'derived/repository_cache/content_addressable/sha256/'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def export_cache(archive, expected, output):
    archive, output = Path(archive), Path(output)
    if not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('explicit lowercase archive SHA256 required')
    if archive.is_symlink() or not archive.is_file() or digest(archive) != expected:
        raise ValueError('archive must be a regular nonsymlink file with the expected SHA256')
    # Exclusive private output preserves failed evidence without exposing a
    # completed cache. Never merge with or overwrite a caller's existing cache.
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    pending = output / 'cache.pending'
    pending.mkdir(mode=0o700)
    receipt = dict(format=1, result='FAIL', archive=str(archive.resolve()),
                   archive_sha256=expected, exporter_sha256=digest(Path(__file__)), entries=[],
                   scope='digest-checked distribution cache; consumer dependency closure unqualified')
    try:
        with zipfile.ZipFile(archive) as source:
            entries = {}
            for info in source.infolist():
                if not info.filename.startswith(PREFIX):
                    continue
                if info.is_dir():
                    continue
                suffix = info.filename[len(PREFIX):]
                if not re.fullmatch('[0-9a-f]{64}/file', suffix):
                    raise ValueError('unexpected repository cache member: ' + info.filename)
                kind = stat.S_IFMT(info.external_attr >> 16)
                if kind not in (0, stat.S_IFREG) or info.flag_bits & 1:
                    raise ValueError('cache member must be an unencrypted regular file')
                if suffix in entries:
                    raise ValueError('duplicate repository cache member')
                entries[suffix] = info
            if not entries:
                raise ValueError('distribution contains no supported repository cache entries')
            for suffix, info in sorted(entries.items()):
                target = pending / 'content_addressable/sha256' / suffix
                target.parent.mkdir(parents=True)
                with source.open(info) as incoming, target.open('xb') as outgoing:
                    shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
                actual = digest(target)
                if actual != suffix.split('/')[0] or target.stat().st_size != info.file_size:
                    raise ValueError('repository cache content digest or size differs')
                receipt['entries'].append(dict(sha256=actual, bytes=info.file_size))
        if digest(archive) != expected:
            raise ValueError('archive changed during export')
        pending.rename(output / 'cache')
        receipt.update(result='PASS', entry_count=len(receipt['entries']))
    except Exception as error:
        receipt['error'] = str(error)
        raise
    finally:
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.output.is_absolute() or not args.output.resolve().is_relative_to('/usr/obj'):
        parser.error('cache export must be below /usr/obj')
    export_cache(args.archive, args.sha256, args.output)
    print(args.output / 'cache')


if __name__ == '__main__':
    main()
