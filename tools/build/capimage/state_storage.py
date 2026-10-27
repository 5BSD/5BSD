#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Explicit two-phase state provisioning in an exclusive offline trusted builder.

Receipts are construction evidence, not authentication or activation authority.
"""
import argparse
import importlib.util
import os
from pathlib import Path

spec = importlib.util.spec_from_file_location('seed_dataset', Path(__file__).with_name('seed_dataset.py'))
dataset = importlib.util.module_from_spec(spec); spec.loader.exec_module(dataset)
image = dataset.image


def bound_file(value, *, executable=False):
    if not isinstance(value, dict) or set(value) != {'path', 'sha256'}:
        raise ValueError('input requires explicit path and SHA256')
    path = Path(value['path'])
    if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_file():
        raise ValueError('input must be a canonical regular file')
    if image.file_hash(path) != value['sha256']:
        raise ValueError('input differs from selected SHA256: ' + str(path))
    if executable and not os.access(path, os.X_OK):
        raise ValueError('selected tool is not executable')
    return path


def bound_json(value):
    path = bound_file(value)
    document, actual = image.construction.generation.read_json(path)
    if actual != value['sha256']:
        raise ValueError('JSON input changed while reading: ' + str(path))
    return document


def prepare(plan):
    if not isinstance(plan, dict) or type(plan.get('format')) is not int or plan['format'] != 1:
        raise ValueError('state plan requires format 1')
    operation = plan.get('operation')
    common = {'format', 'operation', 'tools', 'timeout'}
    fields = {'allocate': {'dataset', 'pool_guid', 'parent_guid'},
              'initialize': {'source', 'observation', 'allocation'}}
    optional = {'execution'} if operation == 'allocate' and 'execution' in plan else set()
    if operation not in fields or set(plan) != common | fields[operation] | optional:
        raise ValueError('invalid state plan operation or fields')
    if type(plan['timeout']) is not int or not 1 <= plan['timeout'] <= 86400:
        raise ValueError('state plan requires timeout 1..86400 seconds')
    required = {'zfs', 'zpool', 'mount'} | ({'tar'} if operation == 'initialize' else set())
    if not isinstance(plan['tools'], dict) or set(plan['tools']) != required:
        raise ValueError('state plan must select every required tool')
    tools = {name: bound_file(value, executable=True) for name, value in plan['tools'].items()}
    if operation == 'allocate':
        if 'execution' in plan and plan['execution'] is None:
            raise ValueError('explicit execution policy cannot be null')
        dataset.execution_policy(plan.get('execution'))
        dataset.dataset_name(plan['dataset'])
        return operation, [plan['dataset'], plan['pool_guid'], plan['parent_guid']], tools
    source = Path(plan['source'])
    if not source.is_absolute() or source.resolve(strict=True) != source or not source.is_dir() or source == Path('/'):
        raise ValueError('state seed must be a canonical alternate directory')
    observation = bound_json(plan['observation'])
    allocation = bound_json(plan['allocation'])
    return operation, [source, observation, allocation], tools


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    plan, plan_hash = image.construction.generation.read_json(args.plan)
    operation, inputs, tools = prepare(plan)
    work = args.output
    if not work.is_absolute() or work.resolve() != work:
        parser.error('output must be a canonical absolute path')
    if image.file_hash(args.plan) != plan_hash:
        raise ValueError('state plan changed before execution')
    function = dataset.allocate if operation == 'allocate' else dataset.initialize_allocated
    options = {'execution': plan.get('execution')} if operation == 'allocate' else {}
    function(*inputs, tools, work, timeout=plan['timeout'], **options)
    image.construction.write_record(work / 'request.json', dict(
        format=1, plan_file_sha256=plan_hash, operation=operation,
        generation_authenticated=False, activation_authorized=False))


if __name__ == '__main__':
    main()
