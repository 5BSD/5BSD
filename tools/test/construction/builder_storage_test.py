#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Real disposable-VM checks for disk-backed builder storage boundaries."""
import importlib.util
import json
import os
from pathlib import Path
import stat
spec = importlib.util.spec_from_file_location('builder_storage', Path(__file__).with_name('builder_storage.py'))
builder_storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder_storage)


def main():
    settings = json.loads(Path('/tests/builder-work.json').read_text())
    work = Path(settings['work'])
    report = builder_storage.prepare(work, '/sbin/mount', '/sbin/sysctl')
    assert report['result'] == 'PASS'
    assert work.stat().st_dev == Path('/').stat().st_dev
    assert work.stat().st_uid == 0 and stat.S_IMODE(work.stat().st_mode) == 0o700
    marker = work / 'retained-candidate-marker'
    with marker.open('xb') as stream:
        stream.write(b'private disk-backed builder workspace\n')
        stream.flush(); os.fsync(stream.fileno())

    def refuse(path):
        try:
            builder_storage.prepare(path, '/sbin/mount', '/sbin/sysctl')
        except ValueError:
            return
        raise AssertionError('unsafe builder path accepted: ' + str(path))

    refuse(work)
    refuse(Path('/'))
    temporary = Path('/tmp/builder-storage-must-not-exist')
    assert not temporary.exists()
    refuse(temporary)
    assert not temporary.exists()
    alias = work / 'alias'
    alias.symlink_to(work, target_is_directory=True)
    refuse(alias / 'must-not-exist')
    assert not (work / 'must-not-exist').exists()
    assert marker.read_bytes() == b'private disk-backed builder workspace\n'
    (work / 'storage-receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    print('BUILDER_STORAGE_PASS: disk-backed private work; occupied, root, tmpfs and symlink paths refused', flush=True)


if __name__ == '__main__':
    main()
