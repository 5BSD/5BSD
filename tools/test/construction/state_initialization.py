# SPDX-License-Identifier: BSD-2-Clause
"""Initialize an allocated private VM disk from verified generation projections.

Caller must independently verify the retained candidate before invoking this
module. Receipts establish construction consistency, never runtime authority.
"""
from pathlib import Path
import os
import re


def select(projections, allocation, state):
    if (not isinstance(allocation, dict) or type(allocation.get('format')) is not int or allocation['format'] != 1 or
            allocation.get('result') != 'PASS' or
            allocation.get('scope') != 'empty-state-dataset-allocation' or
            allocation.get('pool_exported') is not True or
            allocation.get('initialized') is not False or allocation.get('providers')):
        raise ValueError('requires exported, uninitialized ordinary-state allocation')
    rows = allocation.get('bindings')
    if not isinstance(rows, list) or not rows:
        raise ValueError('explicit ordinary-state allocation bindings required')
    receipts, identities, parents, datasets = {}, set(), set(), set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'path', 'receipt'}:
            raise ValueError('invalid state allocation binding')
        path = state.image.construction.generation.pathname(row['path'])
        receipt = row['receipt']
        if path in receipts or not isinstance(receipt, dict):
            raise ValueError('duplicate boundary or invalid allocation receipt')
        if (receipt.get('scope') != 'offline-new-state-allocation' or
                receipt.get('result') != 'PASS' or
                any(receipt.get(key) is not True for key in
                    ('pool_synced', 'left_unmounted', 'dataset_identity_verified'))):
            raise ValueError('requires completed empty dataset allocation receipts')
        for key in ('pool_guid', 'parent_guid', 'dataset_guid'):
            value = receipt.get(key)
            if (not isinstance(value, str) or not re.fullmatch('[1-9][0-9]*', value)
                    or int(value) >= 2**64):
                raise ValueError('invalid allocated GUID')
        name = state.dataset.dataset_name(receipt.get('dataset'))
        identity = (receipt.get('pool_guid'), receipt.get('dataset_guid'))
        if identity in identities or name in datasets:
            raise ValueError('dataset identity reused across state boundaries')
        parents.add((name.rsplit('/', 1)[0], receipt.get('pool_guid'), receipt.get('parent_guid')))
        identities.add(identity); datasets.add(name); receipts[path] = receipt
    if len(parents) != 1:
        raise ValueError('requires a single selected pool and parent')
    seeds = [row for row in projections if row['boundary'] is not None]
    paths = [row['boundary'] for row in seeds]
    if len(paths) != len(set(paths)) or set(paths) != set(receipts):
        raise ValueError('allocation must cover exactly the finalized layout boundaries')
    if any(row['content'] != 'ordinary' for row in seeds):
        raise ValueError('ordinary-state initialization cannot silently provision protected state')
    return [(row, receipts[row['boundary']]) for row in seeds], next(iter(parents))


def initialize(candidate, projections, allocation, tools, work, state, run,
               *, device, timeout):
    """Use the maintained backend against the runner's private output disk.

    The supplied run callable logs commands and enforces its own timeout. The
    caller supplies the independently verified candidate/projections and tools.
    No source disk, allocation artifact or user dataset is replaced on failure.
    """
    if device != '/dev/vtbd2':
        raise ValueError('requires the runner private output disk')
    selected, (parent, pool_guid, parent_guid) = select(projections, allocation, state)
    pool = parent.split('/')[0]
    candidate, work = Path(candidate), Path(work)
    if candidate.is_symlink() or not candidate.is_dir() or candidate.resolve() == Path('/'):
        raise ValueError('requires a physical alternate candidate root')
    if not os.statvfs(candidate).f_flag & os.ST_RDONLY:
        raise ValueError('verified candidate must remain mounted read-only')
    if work.exists() or work.is_symlink() or work.resolve().is_relative_to(candidate.resolve()):
        raise ValueError('state workspace must be new and outside candidate')
    # Validate every seed before importing or modifying the private disk.
    sources = []
    for projection, receipt in selected:
        source = candidate / projection['boundary'].lstrip('/')
        if source.resolve(strict=True) != source or not source.is_dir():
            raise ValueError('state seed must be a physical candidate directory')
        if state.image.construction.generation.scan(source) != projection['observed']:
            raise ValueError('state seed differs from finalized projection')
        sources.append(source)
    work.mkdir(mode=0o700)
    run(str(tools['zpool']), 'import', '-N', '-o', 'cachefile=none', '-d', device, pool_guid)
    receipts = []
    try:
        names = set(run(str(tools['zfs']), 'list', '-H', '-r', '-o', 'name', '-t', 'all', pool).splitlines())
        expected = {pool, parent} | {receipt['dataset'] for _, receipt in selected}
        if names != expected:
            raise ValueError('copied pool contains unexplained datasets or snapshots')
        for index, ((projection, receipt), source) in enumerate(zip(selected, sources)):
            result = state.dataset.initialize_allocated(source, projection['observed'],
                receipt, tools, work / str(index), timeout=timeout)
            receipts.append(dict(path=projection['boundary'], receipt=result))
        run(str(tools['zpool']), 'sync', pool)
    finally:
        # Failure never causes destruction or reseeding. Preserve the copy and
        # per-dataset diagnostics; no aggregate success receipt is issued.
        run(str(tools['zpool']), 'export', pool)
    report = dict(format=1, scope='ordinary-state-initialization', result='PASS',
        bindings=receipts, pool_exported=True, generation_authenticated=False,
        activation_authorized=False, runtime_qualified=False)
    state.image.construction.write_record(work / 'receipt.json', report)
    return report
