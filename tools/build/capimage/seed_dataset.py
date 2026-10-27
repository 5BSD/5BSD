#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Provision initial state in a new ZFS child, in an exclusive offline builder.

No pool creation, recursive dataset creation, existing-state updates, signing,
activation or destructive rollback. Failure retains the new dataset for review.
"""
import importlib.util
import os
from pathlib import Path
import re
import subprocess

spec = importlib.util.spec_from_file_location('seed_initialize', Path(__file__).with_name('seed_initialize.py'))
seed = importlib.util.module_from_spec(spec); spec.loader.exec_module(seed)
image = seed.image


def dataset_name(value):
    if (not isinstance(value, str) or len(value.encode()) > 255 or
            not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.:-]*(/[A-Za-z0-9_][A-Za-z0-9_.:-]*)+', value) or
            any(part in ('.', '..') for part in value.split('/'))):
        raise ValueError('requires an explicit canonical ZFS child dataset')
    return value


def execution_policy(value=None):
    """Execution is owner-selected mount policy, never protected authority."""
    if value is None:
        return {'exec': 'off', 'setuid': 'off'}
    if (not isinstance(value, dict) or set(value) != {'exec', 'setuid'} or
            any(type(v) is not str or v not in ('on', 'off') for v in value.values()) or
            (value['exec'] == 'off' and value['setuid'] == 'on')):
        raise ValueError('execution requires exec/setuid on or off; setuid requires exec')
    return dict(value)


def execution_mount_matches(options, execution):
    return ('rw' in options and 'ro' not in options and
        all((negative in options) == (execution[key] == 'off')
            for key, negative in (('exec', 'noexec'), ('setuid', 'nosuid'))))


def allocate(dataset, pool_guid, parent_guid, tools, work, timeout=600, *, execution=None):
    """Allocate an empty offline child before composing immutable boot policy."""
    return _provision(None, None, dataset, pool_guid, parent_guid, tools, work, timeout,
        execution=execution)


def initialize_allocated(source, expected, allocation, tools, work, timeout=600):
    """Populate only the unchanged empty dataset identified by allocation."""
    if (not isinstance(allocation, dict) or allocation.get('format') != 1 or
            allocation.get('scope') != 'offline-new-state-allocation' or
            allocation.get('result') != 'PASS' or
            any(allocation.get(k) is not True for k in
                ('pool_synced', 'left_unmounted', 'dataset_identity_verified')) or
            any(allocation.get(k) is not False for k in
                ('generation_authenticated', 'activation_authorized', 'runtime_class_assigned')) or
            not re.fullmatch('[0-9a-f]{64}', str(allocation.get('empty_observation_sha256', '')))):
        raise ValueError('requires a completed empty dataset allocation receipt')
    if 'execution' in allocation and allocation['execution'] is None:
        raise ValueError('allocation execution policy cannot be null')
    return _provision(source, expected, allocation['dataset'], allocation['pool_guid'],
        allocation['parent_guid'], tools, work, timeout, allocation=allocation,
        execution=execution_policy(allocation.get('execution')))


def provision(source, expected, dataset, pool_guid, parent_guid, tools, work, timeout=600):
    return _provision(source, expected, dataset, pool_guid, parent_guid, tools, work, timeout)


def _provision(source, expected, dataset, pool_guid, parent_guid, tools, work,
    timeout=600, *, allocation=None, execution=None):
    execution = execution_policy(execution)
    dataset = dataset_name(dataset)
    pool, parent = dataset.split('/')[0], dataset.rsplit('/', 1)[0]
    for value in (pool_guid, parent_guid):
        if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]*', value) or int(value) >= 2**64:
            raise ValueError('explicit pool and parent dataset GUIDs required')
    allocating = source is None
    source, work = (None if allocating else Path(source)), Path(work)
    if not allocating and (source.is_symlink() or not source.is_dir() or source.resolve() == Path('/')):
        raise ValueError('seed source must be an alternate physical directory')
    source = None if allocating else source.resolve(strict=True)
    if work.exists() or work.is_symlink() or (source is not None and work.resolve().is_relative_to(source)):
        raise ValueError('provisioning work must be new and outside seed source')
    required_tools = {'zfs', 'zpool', 'mount'} | (set() if allocating else {'tar'})
    if set(tools) != required_tools:
        raise ValueError('explicit ZFS, pool, mount inventory and archive tools required')
    programs = {}
    for name, value in tools.items():
        path = Path(value)
        if path.is_symlink() or not path.is_file() or (source is not None and path.resolve().is_relative_to(source)):
            raise ValueError('provisioning tools must be external regular files')
        programs[name] = path.resolve(strict=True)
    if os.geteuid() != 0:
        raise PermissionError('fresh dataset provisioning requires a trusted root builder')
    if not allocating and image.construction.generation.scan(source) != expected:
        raise ValueError('seed source differs from selected observations')
    hashes = {name: image.file_hash(path) for name, path in programs.items()}
    def run(name, *args):
        result = subprocess.run([str(programs[name]), *map(str, args)],
            env=image.construction.ENVIRONMENT, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=timeout, close_fds=True)
        if work.exists():
            with (work / 'commands.log').open('a') as log:
                log.write(result.stdout + result.stderr)
        result.check_returncode()
        return result.stdout.strip()
    def prop(name, key):
        return run('zfs', 'get', '-Hp', '-o', 'value', key, name)
    def verify_parent():
        if (run('zpool', 'get', '-Hp', '-o', 'value', 'guid', pool) != pool_guid or
                prop(parent, 'guid') != parent_guid or prop(parent, 'type') != 'filesystem'):
            raise ValueError('selected pool or parent identity differs')
    verify_parent()
    # Enumerate the exact parent subtree. Any command failure aborts; absence
    # is never inferred from an arbitrary failed lookup of the requested name.
    names = run('zfs', 'list', '-H', '-o', 'name', '-r', parent).splitlines()
    if allocation is None and dataset in names:
        raise ValueError('refusing to initialize an existing dataset')
    if allocation is not None:
        if dataset not in names or prop(dataset, 'guid') != allocation.get('dataset_guid'):
            raise ValueError('allocated dataset identity differs')
        for key, value in {'type': 'filesystem', 'mounted': 'no', 'canmount': 'noauto',
                'mountpoint': 'legacy', **execution,
                'devices': 'off', 'readonly': 'off'}.items():
            if prop(dataset, key) != value:
                raise ValueError('allocated dataset property differs: ' + key)
    work.mkdir(mode=0o700); work = work.resolve(strict=True)
    target = work / 'mounted'; target.mkdir(mode=0o700)
    report = dict(format=1, scope=('offline-new-state-allocation' if allocating else 'offline-new-state-dataset'), result='RUNNING',
        dataset=dataset, pool_guid=pool_guid, parent_guid=parent_guid, execution=execution,
        source_observation_sha256=image.construction.digest(expected), tools_sha256=hashes,
        generation_authenticated=False, activation_authorized=False, runtime_class_assigned=False)
    image.construction.write_record(work / 'construction.json', report)
    guid = None
    created = False
    mounted = False
    try:
        verify_parent()
        if allocation is None:
            run('zfs', 'create', '-u', '-o', 'mountpoint=' + str(target),
                '-o', 'canmount=noauto', '-o', 'exec=' + execution['exec'],
                '-o', 'setuid=' + execution['setuid'],
                '-o', 'devices=off', '-o', 'readonly=off', dataset)
        else:
            if prop(dataset, 'guid') != allocation['dataset_guid']:
                raise ValueError('allocated dataset changed before mount setup')
            # Retain the verified identity before a mutation whose command or
            # following query can fail. Cleanup must never adopt a replacement.
            guid = allocation['dataset_guid']
            created = True
            report['dataset_guid'] = guid
            run('zfs', 'set', 'mountpoint=' + str(target), dataset)
            report['allocation_sha256'] = image.construction.digest(allocation)
        created = True
        observed_guid = prop(dataset, 'guid')
        if guid is not None and observed_guid != guid:
            raise ValueError('allocated dataset changed during mount setup')
        guid = observed_guid
        if not re.fullmatch(r'[1-9][0-9]*', guid):
            raise ValueError('invalid new dataset GUID')
        report['dataset_guid'] = guid
        report['stage'] = 'created'
        image.construction.write_record(work / 'construction.json', report)
        run('zfs', 'mount', dataset); mounted = True
        rows = [line.split() for line in run('mount', '-p').splitlines()]
        matching = [row for row in rows if len(row) == 6 and row[0] == dataset]
        if len(matching) != 1:
            raise ValueError('new dataset mount identity is ambiguous')
        row = matching[0]
        mountpoint = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), row[1])
        if (mountpoint != str(target) or row[2] != 'zfs' or
                not execution_mount_matches(set(row[3].split(',')), execution) or
                any(prop(dataset, key) != value for key, value in execution.items()) or
                prop(dataset, 'guid') != guid):
            raise ValueError('new dataset mount identity or options differ')
        if allocating or allocation is not None:
            empty = image.construction.generation.scan(target)
            if set(empty) != {'/'}:
                raise ValueError('allocated dataset contains existing state')
            empty_hash = image.construction.digest(empty)
            if allocation is not None and empty_hash != allocation['empty_observation_sha256']:
                raise ValueError('allocated empty dataset metadata changed')
            report['empty_observation_sha256'] = empty_hash
        if not allocating:
            report['initialization'] = seed.initialize(source, target, expected,
                programs['tar'], work / 'initialization', timeout=timeout)
        verify_parent()
        if prop(dataset, 'guid') != guid:
            raise ValueError('dataset identity changed during initialization')
        run('zfs', 'unmount', dataset); mounted = False
        run('zfs', 'set', 'mountpoint=legacy', dataset)
        if any(prop(dataset, key) != value for key, value in execution.items()):
            raise ValueError('dataset execution policy changed during initialization')
        if prop(dataset, 'mounted') != 'no' or prop(dataset, 'canmount') != 'noauto':
            raise ValueError('initialized dataset not left offline')
        run('zpool', 'sync', pool)
        verify_parent()
        if prop(dataset, 'guid') != guid:
            raise ValueError('dataset identity changed before completion')
        # Publish only the observed final offline state, after pool sync.
        # This is a trusted, exclusive builder check, not a concurrency lock.
        for key, value in {'type': 'filesystem', 'mounted': 'no',
                'mountpoint': 'legacy', 'canmount': 'noauto',
                'devices': 'off', 'readonly': 'off', **execution}.items():
            if prop(dataset, key) != value:
                raise ValueError('final dataset property differs: ' + key)
        # Include the final sync and property reads in tool-stability evidence.
        for name, path in programs.items():
            if image.file_hash(path) != hashes[name]:
                raise ValueError('provisioning tool changed')
        report.update(result='PASS', stage=('allocated-empty-and-synced' if allocating else
                      'initialized-and-synced'), pool_synced=True,
                      dataset_identity_verified=True, left_unmounted=True)
        image.construction.write_record(work / 'receipt.json', report)
        image.construction.write_record(work / 'construction.json', report)
        return report
    except BaseException as error:
        (work / 'receipt.json').unlink(missing_ok=True)
        report.update(result='FAIL', error=str(error), dataset_retained=created)
        report['cleanup'] = dict(status='not-attempted')
        if (mounted or allocation is not None) and guid is not None:
            try:
                if prop(dataset, 'guid') != guid:
                    report['cleanup'] = dict(status='refused-identity-mismatch')
                else:
                    if mounted:
                        run('zfs', 'unmount', dataset)
                    if allocation is not None:
                        # Restore only the verified offline allocation, never
                        # a replacement at the same dataset name.
                        run('zfs', 'set', 'mountpoint=legacy', dataset)
                    report['cleanup'] = dict(status='completed')
            except BaseException as cleanup_error:
                # Preserve the initiating error and record the recovery failure
                # separately. No successful receipt survives either failure.
                report['cleanup'] = dict(status='failed', error=str(cleanup_error))
        image.construction.write_record(work / 'construction.json', report)
        raise
