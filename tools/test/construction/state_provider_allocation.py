#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Extend an exported allocation on a private output disk; never write the input."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
spec = importlib.util.spec_from_file_location('state_readback', Path(__file__).with_name('state_readback.py'))
state_readback = importlib.util.module_from_spec(spec); spec.loader.exec_module(state_readback)


def main():
    state_readback.main()
    spec = importlib.util.spec_from_file_location('state_storage', '/tests/state_storage.py')
    state = importlib.util.module_from_spec(spec); spec.loader.exec_module(state)
    plan, plan_hash = state.image.construction.generation.read_json(Path('/tests/provider-allocation.json'))
    if not isinstance(plan, dict) or set(plan) != {'format', 'dataset', 'recipient', 'input_sha256', 'input_bytes'} or type(plan['format']) is not int or plan['format'] != 1:
        raise ValueError('invalid provider allocation plan')
    dataset = state.dataset.dataset_name(plan['dataset'])
    if not isinstance(plan['recipient'], str) or plan['recipient'].count('/') != 1:
        raise ValueError('explicit provider recipient required')
    if type(plan['input_bytes']) is not int or (plan['input_bytes'] < 128 * 1024 * 1024 or plan['input_bytes'] % 512):
        raise ValueError('explicit disk size required')
    if Path('/tests/output-device').read_text().strip() != '/dev/vtbd2':
        raise ValueError('requires private runner output disk')
    original = json.loads(Path('/tests/state-allocation-result.json').read_text())
    if original.get('providers'):
        raise ValueError('provider extension requires the ordinary allocation input')
    receipts = [row['receipt'] for row in original['bindings']]
    parent = dataset.rsplit('/', 1)[0]
    if any(r['dataset'].rsplit('/', 1)[0] != parent or r['dataset'] == dataset for r in receipts):
        raise ValueError('provider must be a new sibling of ordinary datasets')
    # Exact copy, with byte count and content checks, onto a newly created output.
    hashed = hashlib.sha256(); remaining = plan['input_bytes']
    with open('/dev/vtbd1', 'rb', buffering=0) as source, open('/dev/vtbd2', 'r+b', buffering=0) as target:
        while remaining:
            data = source.read(min(1024 * 1024, remaining))
            if not data: raise ValueError('short input disk')
            hashed.update(data)
            view = memoryview(data)
            while view:
                count = target.write(view)
                if not count: raise OSError('short disk write')
                view = view[count:]
            remaining -= len(data)
        if source.read(512) or hashed.hexdigest() != plan['input_sha256']:
            raise ValueError('input size or digest differs')
        os.fsync(target.fileno())
        target.seek(0); copied = hashlib.sha256(); remaining = plan['input_bytes']
        while remaining:
            data = target.read(min(1024 * 1024, remaining))
            if not data: raise ValueError('short output disk')
            copied.update(data); remaining -= len(data)
        if copied.hexdigest() != plan['input_sha256']:
            raise ValueError('copied disk differs')
    pool = dataset.split('/')[0]; guid = receipts[0]['pool_guid']
    subprocess.run(['/sbin/zpool', 'import', '-N', '-o', 'cachefile=none', '-d', '/dev/vtbd2', guid], check=True, timeout=120)
    try:
        tools = {name: dict(path='/sbin/' + name, sha256=state.image.file_hash(Path('/sbin') / name)) for name in ('zfs', 'zpool', 'mount')}
        selected = dict(format=1, operation='allocate', timeout=120, tools=tools, dataset=dataset, pool_guid=guid, parent_guid=receipts[0]['parent_guid'])
        _, inputs, programs = state.prepare(selected)
        receipt = state.dataset.allocate(*inputs, programs, Path('/tmp/provider-allocation'), timeout=120)
    finally:
        subprocess.run(['/sbin/zpool', 'export', pool], check=True, timeout=120)
    original.update(providers=[dict(recipient=plan['recipient'], receipt=receipt)], provider_plan_sha256=plan_hash, source_disk_sha256=plan['input_sha256'])
    print('STATE_PROVIDER_ALLOCATION_RESULT ' + json.dumps(original, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
