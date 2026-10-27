#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Allocate explicitly selected state datasets on a fresh disposable VM disk.

Leaves an exported pool for subsequent construction, not accepted runtime state.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time


def validate_plan(plan, state):
    if (not isinstance(plan, dict) or type(plan.get('format')) is not int or
            plan['format'] not in (1, 2) or set(plan) !=
            ({'format', 'parent', 'bindings', 'layout'} |
             ({'providers'} if plan['format'] == 2 else set()))):
        raise ValueError('invalid allocation plan')
    parent = state.dataset.dataset_name(plan['parent'])
    if parent.count('/') != 1:
        raise ValueError('select a direct child of the new pool as parent')
    pool = parent.split('/')[0]
    layout = state.bound_json(plan['layout'])
    if not isinstance(layout, dict) or set(layout) != {'format', 'boundaries'} or layout['format'] != 1:
        raise ValueError('invalid selected layout')
    paths = [state.image.construction.generation.pathname(r['path']) for r in layout['boundaries']]
    bindings = plan['bindings']
    if not isinstance(bindings, list):
        raise ValueError('explicit bindings required')
    mapped, datasets = set(), set()
    for row in bindings:
        if not isinstance(row, dict) or set(row) not in ({'path', 'dataset'}, {'path', 'dataset', 'execution'}):
            raise ValueError('invalid allocation binding')
        path = state.image.construction.generation.pathname(row['path'])
        name = state.dataset.dataset_name(row['dataset'])
        if name.rsplit('/', 1)[0] != parent or path in mapped or name in datasets:
            raise ValueError('duplicate binding or dataset outside selected parent')
        if 'execution' in row and row['execution'] is None:
            raise ValueError('explicit execution policy cannot be null')
        state.dataset.execution_policy(row.get('execution'))
        mapped.add(path); datasets.add(name)
    if len(set(paths)) != len(paths) or mapped != set(paths):
        raise ValueError('allocation must cover exactly the selected layout')
    providers = plan.get('providers', [])
    if not isinstance(providers, list) or not (bindings or providers):
        raise ValueError('explicit dataset allocations required')
    recipients = set()
    for row in providers:
        if (not isinstance(row, dict) or set(row) not in
                ({'recipient', 'dataset'}, {'recipient', 'dataset', 'execution'})):
            raise ValueError('invalid provider allocation fields')
        recipient = row['recipient']
        if (not isinstance(recipient, str) or not recipient or
                len(recipient.encode()) > 255 or
                any(c.isspace() or c == '\0' for c in recipient) or recipient in recipients):
            raise ValueError('invalid or duplicate provider recipient')
        name = state.dataset.dataset_name(row['dataset'])
        if name.rsplit('/', 1)[0] != parent or name in datasets:
            raise ValueError('duplicate provider dataset or outside selected parent')
        if 'execution' in row and row['execution'] is None:
            raise ValueError('explicit execution policy cannot be null')
        state.dataset.execution_policy(row.get('execution'))
        recipients.add(recipient); datasets.add(name)
    return parent, bindings, providers


def main():
    started = time.monotonic()

    def progress(phase, **details):
        # Diagnostic records are not allocation receipts or acceptance evidence.
        print('STATE_ALLOCATION_PROGRESS ' + json.dumps(dict(
            phase=phase, elapsed_seconds=round(time.monotonic() - started, 3),
            **details), sort_keys=True), flush=True)

    def run(*argv):
        progress('command-start', argv=argv)
        result = subprocess.check_output(argv, text=True, timeout=120).strip()
        progress('command-complete', argv=argv)
        return result

    progress('start')
    if os.geteuid() != 0 or run('/sbin/sysctl', '-n', 'kern.vm_guest') in ('', 'none'):
        raise ValueError('requires a disposable VM')
    device = Path('/tests/scratch-device').read_text().strip()
    if device != '/dev/vtbd1':
        raise ValueError('requires the runner-created scratch device')
    progress('backend-import-start')
    spec = importlib.util.spec_from_file_location('state_storage', '/tests/state_storage.py')
    state = importlib.util.module_from_spec(spec); spec.loader.exec_module(state)
    progress('backend-import-complete')
    plan, plan_hash = state.image.construction.generation.read_json(Path('/tests/state-allocation.json'))
    parent, bindings, providers = validate_plan(plan, state)
    progress('plan-validated', bindings=len(bindings), providers=len(providers))
    pool = parent.split('/')[0]
    work = Path('/tmp/state-allocation'); work.mkdir(mode=0o700)
    # No force: even the disposable role does not authorize replacing an existing pool.
    run('/sbin/zpool', 'create', '-o', 'cachefile=none', '-O', 'mountpoint=none', pool, device)
    run('/sbin/zfs', 'create', '-o', 'mountpoint=none', parent)
    pool_guid = run('/sbin/zpool', 'get', '-Hp', '-o', 'value', 'guid', pool)
    parent_guid = run('/sbin/zfs', 'get', '-Hp', '-o', 'value', 'guid', parent)
    progress('tool-hashing-start')
    tools = {name: dict(path='/sbin/' + name, sha256=state.image.file_hash(Path('/sbin') / name)) for name in ('zfs', 'zpool', 'mount')}
    progress('tool-hashing-complete')
    receipts, provider_receipts = [], []
    for index, row in enumerate(bindings + providers):
        selected = dict(format=1, operation='allocate', timeout=120, tools=tools,
                        dataset=row['dataset'], pool_guid=pool_guid, parent_guid=parent_guid)
        if 'execution' in row:
            selected['execution'] = row['execution']
        progress('dataset-prepare-start', dataset=row['dataset'])
        operation, inputs, programs = state.prepare(selected)
        progress('dataset-allocation-start', dataset=row['dataset'])
        receipt = state.dataset.allocate(*inputs, programs, work / str(index),
            timeout=selected['timeout'], execution=selected.get('execution'))
        progress('dataset-allocation-complete', dataset=row['dataset'])
        if index < len(bindings):
            receipts.append(dict(path=row['path'], receipt=receipt))
        else:
            provider_receipts.append(dict(recipient=row['recipient'], receipt=receipt))
    run('/sbin/zpool', 'export', pool)
    result = dict(format=1, result='PASS', scope='empty-state-dataset-allocation',
                  plan_sha256=plan_hash, bindings=receipts, pool_exported=True,
                  generation_authenticated=False, initialized=False, runtime_qualified=False)
    if plan['format'] == 2:
        result['providers'] = provider_receipts
    print('STATE_ALLOCATION_RESULT ' + json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
