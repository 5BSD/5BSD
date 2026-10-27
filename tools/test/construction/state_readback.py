#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Read back allocated dataset identities from a hash-bound, read-only VM disk."""
import hashlib
import importlib.util
import json
import os
import errno
import re
import uuid
from pathlib import Path
import subprocess



def selection(document):
    """Select empty allocation or completed initialization evidence."""
    initialized = document.get('scope') == 'initialized-state-vm-transport'
    selected = document.get('report') if initialized else document
    if initialized and (document.get('format') != 1 or
            not re.fullmatch('[0-9a-f]{64}', str(document.get('output_disk_sha256', '')))):
        raise ValueError('initialized state requires its transported output disk hash')
    scope = 'ordinary-state-initialization' if initialized else 'empty-state-dataset-allocation'
    if (not isinstance(selected, dict) or selected.get('result') != 'PASS' or
            selected.get('scope') != scope or selected.get('pool_exported') is not True):
        raise ValueError('requires exported successful state evidence')
    rows = selected.get('bindings', []) + selected.get('providers', [])
    if not rows:
        raise ValueError('empty state evidence')
    identities, datasets, boundaries = set(), set(), set()
    for row in rows:
        receipt = row['receipt']
        for key in ('pool_guid', 'parent_guid', 'dataset_guid'):
            value = receipt.get(key)
            if not isinstance(value, str) or not re.fullmatch('[1-9][0-9]*', value) or int(value) >= 2**64:
                raise ValueError('invalid selected state GUID')
        identity = (receipt['pool_guid'], receipt['dataset_guid'])
        name = receipt.get('dataset')
        if not isinstance(name, str) or not name:
            raise ValueError('selected state requires a dataset name')
        if identity in identities or name in datasets:
            raise ValueError('duplicate selected dataset identity or name')
        identities.add(identity); datasets.add(name)
        if initialized:
            boundary = row.get('path')
            if (not isinstance(boundary, str) or not boundary.startswith('/') or
                    boundary == '/' or any(part in ('', '.', '..') for part in boundary.split('/')[1:]) or
                    any(ord(c) < 32 or ord(c) == 127 for c in boundary)):
                raise ValueError('initialized state requires a canonical writable boundary')
            if boundary in boundaries:
                raise ValueError('duplicate selected writable boundary')
            boundaries.add(boundary)
            expected = receipt.get('source_observation_sha256')
            copied = receipt.get('initialization', {})
            if (receipt.get('scope') != 'offline-new-state-dataset' or receipt.get('result') != 'PASS' or
                    not re.fullmatch('[0-9a-f]{64}', str(expected)) or
                    copied.get('scope') != 'offline-empty-state-initialization' or copied.get('result') != 'PASS' or
                    copied.get('source_observation_sha256') != expected or
                    copied.get('initialized_observation_sha256') != expected):
                raise ValueError('initialized dataset lacks matching seed observations')
    return rows, initialized


def main():
    def run(*args):
        return subprocess.check_output(args, text=True, timeout=120).strip()
    if os.geteuid() != 0 or run('/sbin/sysctl', '-n', 'kern.vm_guest') in ('', 'none'):
        raise ValueError('requires a disposable VM')
    device = Path('/tests/input-device').read_text().strip()
    if device != '/dev/vtbd1':
        raise ValueError('requires the runner read-only input device')
    raw = Path('/tests/state-allocation-result.json').read_bytes()
    selected = json.loads(raw)
    rows, initialized = selection(selected)
    spec = importlib.util.spec_from_file_location('state_storage', '/tests/state_storage.py')
    state = importlib.util.module_from_spec(spec); spec.loader.exec_module(state)
    pools = {r['receipt']['pool_guid'] for r in rows}
    parents = {r['receipt']['dataset'].rsplit('/', 1)[0] for r in rows}
    if len(pools) != 1 or len(parents) != 1:
        raise ValueError('requires one selected pool and parent')
    pool_guid = pools.pop(); parent = parents.pop(); pool = parent.split('/')[0]
    for row in rows:
        state.dataset.dataset_name(row['receipt']['dataset'])
    run('/sbin/zpool', 'import', '-N', '-o', 'readonly=on', '-o', 'cachefile=none', '-d', device, pool_guid)
    try:
        def prop(name, key):
            return run('/sbin/zfs', 'get', '-Hp', '-o', 'value', key, name)
        if run('/sbin/zpool', 'get', '-Hp', '-o', 'value', 'guid', pool) != pool_guid or run('/sbin/zpool', 'get', '-Hp', '-o', 'value', 'readonly', pool) != 'on':
            raise ValueError('pool identity or read-only import differs')
        expected = {pool, parent} | {r['receipt']['dataset'] for r in rows}
        actual = set(run('/sbin/zfs', 'list', '-H', '-r', '-o', 'name', '-t', 'all', pool).splitlines())
        if actual != expected:
            raise ValueError('dataset inventory differs from allocated identities')
        for row in rows:
            receipt = row['receipt']; name = receipt['dataset']
            if prop(parent, 'guid') != receipt['parent_guid'] or prop(name, 'guid') != receipt['dataset_guid']:
                raise ValueError('allocated parent or child identity differs')
            if 'execution' in receipt and receipt['execution'] is None:
                raise ValueError('explicit execution policy cannot be null')
            execution = state.dataset.execution_policy(receipt.get('execution'))
            for key, value in dict(mounted='no', mountpoint='legacy', canmount='noauto', devices='off', **execution).items():
                if prop(name, key) != value:
                    raise ValueError('allocated property differs: ' + name + ':' + key)
            if initialized:
                target = Path('/tmp') / ('state-readback-' + uuid.uuid4().hex)
                target.mkdir(mode=0o700)
                run('/sbin/mount', '-t', 'zfs', '-o', 'ro', name, str(target))
                try:
                    if not os.statvfs(target).f_flag & os.ST_RDONLY:
                        raise ValueError('initialized state mount is writable')
                    try:
                        with (target / ('write-refusal-' + uuid.uuid4().hex)).open('xb'):
                            pass
                    except OSError as error:
                        if error.errno != errno.EROFS:
                            raise
                    else:
                        raise ValueError('initialized state allowed file creation')
                    observed = state.image.construction.generation.scan(target)
                    if state.image.construction.digest(observed) != receipt['source_observation_sha256']:
                        raise ValueError('cold state contents differ from finalized seed: ' + name)
                finally:
                    run('/sbin/umount', str(target))
                    target.rmdir()
    finally:
        run('/sbin/zpool', 'export', pool)
    print('STATE_READBACK_PASS ' + json.dumps(dict(bindings=len(rows), allocation_sha256=hashlib.sha256(raw).hexdigest(), contents_verified=initialized, expected_disk_sha256=selected.get("output_disk_sha256") if initialized else None, runtime_qualified=False)), flush=True)


if __name__ == '__main__':
    main()
