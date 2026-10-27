#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Independently check retained builder output mounted read-only.

This verifies post-shutdown consistency, not release authentication or policy
approval. Helpers and SQLite must come from the verifier, never the input disk.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat


def layout_receipt_binding(path, expected=None):
    """Bind the complete exported receipt without repeating it on serial."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 64 * 1024 * 1024:
            raise ValueError('invalid layout receipt file or size')
        hashed, count = hashlib.sha256(), 0
        chunks = [] if expected is not None else None
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            count += len(block)
            if count > info.st_size:
                raise ValueError('layout receipt grew during binding')
            hashed.update(block)
            if chunks is not None:
                chunks.append(block)
        if count != info.st_size:
            raise ValueError('layout receipt size changed during binding')
        if chunks is not None and json.loads(b''.join(chunks)) != expected:
            raise ValueError('layout receipt differs from materialization result')
    return {'format': 1, 'scope': 'split-layout-receipt-binding',
            'bytes': count, 'sha256': hashed.hexdigest()}


def verify_layout_receipt_binding(path, binding):
    if (not isinstance(binding, dict) or
            set(binding) != {'format', 'scope', 'bytes', 'sha256'} or
            type(binding['format']) is not int or binding['format'] != 1 or
            type(binding['bytes']) is not int or
            binding['scope'] != 'split-layout-receipt-binding' or
            not isinstance(binding['sha256'], str) or
            re.fullmatch('[0-9a-f]{64}', binding['sha256']) is None):
        raise ValueError('invalid verifier receipt binding')
    if layout_receipt_binding(path) != binding:
        raise ValueError('collected split layout differs from verifier receipt binding')


def rooted(root, name, directory=False):
    if (not isinstance(name, str) or not name.startswith('/') or name == '/' or
            any(part in ('', '.', '..') for part in name.split('/')[1:])):
        raise ValueError('invalid retained-artifact pathname')
    path = root / name.lstrip('/')
    if path.resolve(strict=True) != path or not path.is_relative_to(root):
        raise ValueError('retained path crosses a symlink or artifact boundary')
    if not (path.is_dir() if directory else path.is_file()):
        raise ValueError('unexpected retained object type: ' + name)
    if path.stat().st_dev != root.stat().st_dev:
        raise ValueError('retained path crosses a mount boundary')
    return path


def construction_diagnostics(root, work):
    """Read bounded tails of known builder outputs; never approve their content."""
    rooted(root, work, directory=True)
    records = {}
    for relative in ('retained-builder.json',
                     'construction/constructed/construction.json',
                     'construction/constructed/database/construction.json',
                     'construction/constructed/database/registration.log',
                     'construction/constructed/database/receipt.json'):
        try:
            path = rooted(root, work + '/' + relative)
        except FileNotFoundError:
            records[relative] = {'present': False}
            continue
        with path.open('rb') as stream:
            size = os.fstat(stream.fileno()).st_size
            stream.seek(max(0, size - 4096))
            tail = stream.read(4096)
        records[relative] = dict(present=True, size=size, truncated=size > len(tail),
            tail_sha256=hashlib.sha256(tail).hexdigest(),
            tail_utf8=tail.decode('utf-8', errors='replace'))
    return {'scope': 'untrusted builder diagnostics only', 'candidate_verified': False,
            'records': records}


def load_helpers(helpers, root):
    helpers = helpers.resolve(strict=True)
    if helpers.is_relative_to(root):
        raise ValueError('verifier helpers cannot come from the input artifact')
    modules = {}
    for name in ('construction', 'database_construction'):
        spec = importlib.util.spec_from_file_location(name, helpers / (name + '.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        modules[name] = module
    return modules['construction'], modules['database_construction']


def reviewed_state(constructor, inventory, objects):
    """Carry independently observed state needs forward without approving grants."""
    bindings, differences = constructor.generation.state_consumer_bindings(inventory, objects)
    if differences:
        raise ValueError('retained state consumer differs from package payload')
    return {'format': 1, 'scope': 'retained-generation-state-review',
            'inventory_sha256': constructor.digest(inventory),
            'filesystem_sha256': constructor.digest(objects),
            'declarations': constructor.pkg.state_requirements(inventory['packages']),
            'consumer_bindings': bindings,
            'layout': constructor.generation.state_layout_review(inventory, objects),
            'authority_assigned': False, 'coverage_complete': False,
            'runtime_qualified': False}


def verify_constructed_layout(constructor, inventory, objects, policy, saved, binding):
    """Recompute the construction-time layout from the final retained objects."""
    actual = constructor.generation.storage_layout(inventory, objects, policy)
    expected = dict(policy_sha256=constructor.digest(policy),
        layout_sha256=constructor.digest(actual), filesystem_sha256=constructor.digest(objects),
        authority_assigned=False, coverage_complete=False, runtime_qualified=False)
    if saved != actual or binding != expected:
        raise ValueError('retained construction storage layout differs from final filesystem or policy')
    return expected


def reviewed_layout(constructor, inventory, objects, policy_path):
    """Validate explicit boundaries against the whole reconciled observation."""
    policy, policy_hash = constructor.generation.read_json(policy_path)
    layout = constructor.generation.storage_layout(inventory, objects, policy)
    return dict(scope='retained-generation-storage-layout',
        policy_file_sha256=policy_hash, inventory_sha256=constructor.digest(inventory),
        filesystem_sha256=constructor.digest(objects),
        immutable_object_count=len(layout['immutable_objects']),
        boundaries=[dict(path=row['path'], content=row['content'],
            seed_object_count=len(row['seed_objects']),
            seed_observation_sha256=constructor.digest(row['seed_objects']))
            for row in layout['boundaries']], requirements=layout['requirements'],
        authority_assigned=False, coverage_complete=False, runtime_qualified=False)


def collect_verification(work):
    """Retain one guest report only after an unforced, unchanged-input VM result."""
    work = Path(work)
    vm = work / 'vm'
    result_bytes = (vm / 'result.json').read_bytes()
    serial_bytes = (vm / 'serial.log').read_bytes()
    result = json.loads(result_bytes)
    serial_hash = hashlib.sha256(serial_bytes).hexdigest()
    disk_hash = result.get('input_disk_sha256')
    if (result.get('result') != 'PASS' or result.get('forced_termination') is not False or
            result.get('qemu_exit') != 0 or result.get('input_disk_readonly') is not True or
            not isinstance(disk_hash, str) or not re.fullmatch('[0-9a-f]{64}', disk_hash) or
            result.get('input_disk_final_sha256') != disk_hash or
            result.get('serial_sha256') != serial_hash):
        raise ValueError('retained verifier VM evidence is incomplete or changed')
    prefix = 'RETAINED_VERIFICATION_RESULT '
    records = [json.loads(line[len(prefix):]) for line in serial_bytes.decode().splitlines()
               if line.startswith(prefix)]
    if len(records) != 1:
        raise ValueError('requires exactly one retained verification report')
    report = records[0]
    if (not isinstance(report, dict) or report.get('result') != 'PASS' or
            report.get('scope') != 'retained-builder-post-shutdown-consistency' or
            report.get('generation_authenticated') is not False or
            report.get('policy_approval_verified') is not False or
            report.get('normal_boot_qualified') is not False):
        raise ValueError('invalid retained verification report')
    review = report.get('state_review')
    if (not isinstance(review, dict) or
            review.get('scope') != 'retained-generation-state-review' or
            any(review.get(key) is not False for key in
                ('authority_assigned', 'coverage_complete', 'runtime_qualified')) or
            any(not isinstance(report.get(key), str) or
                not re.fullmatch('[0-9a-f]{64}', report[key]) or
                review.get(key) != report[key] for key in
                ('inventory_sha256', 'filesystem_sha256'))):
        raise ValueError('state review does not bind the verified generation')
    relocation = report.get('construction_relocation')
    if relocation is not None and (
            not isinstance(relocation, dict) or
            relocation.get('filesystem_sha256') != report['filesystem_sha256'] or
            type(relocation.get('moves')) is not int or relocation['moves'] < 1 or
            any(relocation.get(key) is not False for key in
                ('generation_authenticated', 'runtime_authority_assigned')) or
            any(not isinstance(relocation.get(key), str) or
                not re.fullmatch('[0-9a-f]{64}', relocation[key]) for key in
                ('policy_sha256', 'receipt_sha256'))):
        raise ValueError('relocation review does not bind the verified generation')
    selected = work / 'extra/tests/storage-layout-policy.json'
    layout = report.get('storage_layout_review')
    if selected.exists():
        if (not isinstance(layout, dict) or
                layout.get('scope') != 'retained-generation-storage-layout' or
                layout.get('policy_file_sha256') != hashlib.sha256(selected.read_bytes()).hexdigest() or
                any(layout.get(key) != report[key] for key in
                    ('inventory_sha256', 'filesystem_sha256')) or
                any(layout.get(key) is not False for key in
                    ('authority_assigned', 'coverage_complete', 'runtime_qualified'))):
            raise ValueError('storage layout review does not bind selected policy and generation')
    elif layout is not None:
        raise ValueError('storage layout review lacks selected policy')
    evidence = {'format': 1, 'scope': 'retained-verifier-report-transport',
        'vm_result_sha256': hashlib.sha256(result_bytes).hexdigest(),
        'serial_sha256': serial_hash, 'input_disk_sha256': disk_hash,
        'generation_authenticated': False, 'activation_authorized': False,
        'report': report}
    with (work / 'verification.json').open('x') as stream:
        json.dump(evidence, stream, sort_keys=True, indent=2)
        stream.write('\n')
    return evidence


def verify_installation(root, candidate, output_name, built, generated, initial, inventory, constructor):
    """Check policy bindings; the caller also verifies the read-only artifact/tree."""
    read = constructor.generation.read_json
    transport_path = Path(__file__).with_name('installation_transport.py')
    spec = importlib.util.spec_from_file_location('installation_transport', transport_path)
    transport = importlib.util.module_from_spec(spec); spec.loader.exec_module(transport)
    policy, transport_receipt = transport.verify(rooted(root, '/tests', directory=True))
    saved_transport, _ = read(rooted(root, output_name + '/installation-transport.json'))
    if transport_receipt != saved_transport:
        raise ValueError('retained installation transport receipt differs')
    mapped_policy = copy.deepcopy(policy)
    for entry in mapped_policy['entries'].values():
        if not transport.is_candidate_path(policy, entry):
            entry['source'] = str(rooted(root, entry['source']))
    plan = constructor.installations.prepare(inventory,
        constructor.generation.expected_objects(inventory, initial), initial,
        mapped_policy, candidate, constructor._construction_context())
    policy_hash = constructor.digest(policy)
    for entry in plan['records'].values():
        entry['source'] = 'installation policy sha256:' + policy_hash
    moves = constructor.installations.relocation_requests(inventory, policy, constructor._construction_context())
    if bool(moves) != (built.get('installation_relocation') is not None):
        raise ValueError('retained relocation receipt presence differs from policy')
    receipt = built['installation_configuration']
    if (receipt.get('policy_sha256') != policy_hash or
            receipt.get('records') != plan['records'] or
            receipt.get('sources') != {name: entry['source'] for name, entry in policy['entries'].items()
                                     if not transport.is_candidate_path(policy, entry)} or
            any(generated['entries'].get(name) != entry for name, entry in plan['records'].items())):
        raise ValueError('retained installation configuration differs from explicit inputs')
    return policy


def verify_relocations(candidate, constructor, inventory, initial, built, generated, objects, policy):
    """Reverse declared moves in the measured tree and recheck their provenance."""
    c = constructor
    moves = c.installations.relocation_requests(inventory, policy, c._construction_context())
    saved = built.get('installation_relocation')
    if not moves or not isinstance(saved, dict):
        raise ValueError('retained relocation requires declared moves and a receipt')
    before_generated = copy.deepcopy(initial)
    installation = built['installation_configuration']
    before_generated['entries'].update(installation['records'])
    previous_hash = installation['after_sha256']
    for receipt in built['receipts']:
        body = {key: value for key, value in receipt.items() if key != 'sha256'}
        if receipt.get('sha256') != c.digest(body) or receipt.get('before_sha256') != previous_hash:
            raise ValueError('relocation construction receipt chain differs')
        if receipt.get('scope') == 'database-generation-installation':
            prefix = 'database installation receipt sha256:'
        elif 'action' in receipt:
            prefix = 'construction receipt sha256:'
        else:
            raise ValueError('unknown relocation predecessor receipt')
        for path, record in receipt['outputs'].items():
            before_generated['entries'][path] = dict(record, source=prefix + receipt['sha256'])
        previous_hash = receipt['after_sha256']
    before = copy.deepcopy(objects)
    for name, move in moves.items():
        target = move['target']
        if target not in before:
            raise ValueError('relocated file missing from measured filesystem')
        before[name] = before.pop(target)
    parents = {str(Path(path).parent) for name, move in moves.items()
               for path in (name, move['target'])}
    saved_parents = saved.get('parent_observations')
    if not isinstance(saved_parents, dict) or set(saved_parents) != parents:
        raise ValueError('relocation parent observation set differs')
    for path in parents:
        original, current = saved_parents[path], objects.get(path, {})
        if (not isinstance(original, dict) or original.get('type') != 'directory' or
                {k: v for k, v in original.items() if k not in ('mtime', 'mtime_nsec')} !=
                {k: v for k, v in current.items() if k not in ('mtime', 'mtime_nsec')}):
            raise ValueError('relocation changed parent metadata beyond timestamps')
        before[path] = original
    if c.digest(before) != saved.get('before_sha256') or saved['before_sha256'] != previous_hash:
        raise ValueError('relocation prior filesystem differs from predecessor')
    prior_expected = c.generation.expected_objects(inventory, before_generated)
    named = any(prior_expected.get(name, {}).get('uname') or
                prior_expected.get(name, {}).get('gname') for name in moves)
    users, groups = c.generation.account_maps(candidate,
        c.generation.expected_objects(inventory, generated), objects) if named else ({}, {})
    for name in moves:
        wanted = dict(prior_expected.get(name, {}))
        for label, numeric, mapping in (('uname', 'uid', users), ('gname', 'gid', groups)):
            if wanted.get(label):
                if wanted[label] not in mapping:
                    raise ValueError('unknown relocated generation owner')
                wanted[numeric] = mapping[wanted[label]]
        keys = ['type', 'uid', 'gid', 'mode', 'flags_set', 'sha256', 'size', 'hardlinks']
        keys += [key for key in ('mtime', 'mtime_nsec') if key in wanted]
        if wanted.get('type') != 'file' or any(wanted.get(key) != before[name].get(key) for key in keys):
            raise ValueError('relocation source differs from prior declared content or metadata')
    plan = c.installations.prepare_relocations(inventory, before, before_generated,
                                               policy, c._construction_context())
    expected_receipt = dict(plan, scope='trusted-builder-installation-relocation',
                           before_sha256=c.digest(before), after_sha256=c.digest(objects))
    if saved != expected_receipt:
        raise ValueError('retained relocation receipt differs from reconstructed moves')
    before_generated['entries'].update(plan['records'])
    if generated != before_generated:
        raise ValueError('relocation final manifest differs from predecessor and moves')
    return dict(policy_sha256=c.digest(policy), receipt_sha256=c.digest(saved),
                filesystem_sha256=c.digest(objects), moves=len(moves),
                generation_authenticated=False, runtime_authority_assigned=False)


def verify(root, work, helpers, sqlite, *, with_observation=False, storage_layout_policy=None, with_inventory=False):
    root = Path(root)
    if root.is_symlink() or not root.is_dir() or root.resolve() == Path('/'):
        raise ValueError('requires a separately mounted artifact root')
    root = root.resolve(strict=True)
    if not os.statvfs(root).f_flag & os.ST_RDONLY:
        raise ValueError('artifact filesystem must be mounted read-only')
    workspace = rooted(root, work, directory=True)
    constructor, database = load_helpers(Path(helpers), root)
    sqlite = Path(sqlite).resolve(strict=True)
    if sqlite.is_relative_to(root):
        raise ValueError('SQLite verifier cannot come from the input artifact')
    read = constructor.generation.read_json
    retained, retained_hash = read(workspace / 'retained-builder.json')
    candidate_name = work + '/construction/candidate'
    output_name = work + '/construction/constructed'
    built, _ = read(rooted(root, output_name + '/construction.json'))
    expected_receipts = {output_name + suffix for suffix in
                         ('/construction.json', '/generated.json', '/database/receipt.json')}
    if built.get('installation_configuration') is not None:
        expected_receipts.add(output_name + '/installation-transport.json')
    if built.get('storage_layout') is not None:
        expected_receipts.add(output_name + '/storage-layout.json')
    if (retained.get('format') != 1 or retained.get('result') != 'PASS' or
            retained.get('scope') != 'retained-trusted-builder-output' or
            retained.get('candidate') != candidate_name or
            set(retained.get('receipts_sha256', {})) != expected_receipts):
        raise ValueError('retained success record differs from expected workspace layout')
    for name, expected in retained['receipts_sha256'].items():
        path = rooted(root, name)
        if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected):
            raise ValueError('invalid retained receipt hash')
        if database.payload.preflight.file_hash(path) != expected:
            raise ValueError('retained receipt changed: ' + name)
    candidate = rooted(root, candidate_name, directory=True)
    built, _ = read(rooted(root, output_name + '/construction.json'))
    generated, _ = read(rooted(root, output_name + '/generated.json'))
    accepted, _ = read(rooted(root, output_name + '/database/receipt.json'))
    initial, _ = read(rooted(root, '/tests/system-layout.json'))
    record, _ = read(rooted(root, '/tests/system-inventory.json'))
    if (built.get('result') != 'PASS' or built.get('scope') != 'trusted-builder-construction' or
            built.get('generated_sha256') != constructor.digest(generated) or
            built.get('initial_generated_sha256') != constructor.digest(initial)):
        raise ValueError('construction receipt or generated inputs differ')
    # Relocate archive references without changing their identities or metadata.
    mapped = copy.deepcopy(record)
    original_names = {}
    for item in mapped['packages']:
        original = item['archive']
        path = rooted(root, original)
        if str(path) in original_names:
            raise ValueError('duplicate retained archive reference')
        original_names[str(path)] = original
        item['archive'] = str(path)
    inventory = constructor.inventory_from_archives(mapped)
    canonical = copy.deepcopy(inventory)
    for package in canonical['packages']:
        package['archive'] = original_names[package['archive']]
    inventory_hash = constructor.digest(canonical)
    if inventory_hash != built.get('inventory_sha256'):
        raise ValueError('re-read archives differ from construction inventory')
    installation_policy = None
    if built.get('installation_configuration') is not None:
        installation_policy = verify_installation(root, candidate, output_name, built, generated, initial, inventory, constructor)
    elif built.get('installation_relocation') is not None:
        raise ValueError('relocation receipt lacks installation policy binding')

    if (accepted.get('result') != 'PASS' or
            accepted.get('scope') != 'trusted-builder-database-construction' or
            accepted.get('inventory_sha256') != inventory_hash or
            built.get('database_construction_sha256') != constructor.digest(accepted)):
        raise ValueError('database construction receipt differs')
    for receipt in built['receipts']:
        body = {key: value for key, value in receipt.items() if key != 'sha256'}
        if receipt.get('sha256') != constructor.digest(body):
            raise ValueError('construction action receipt changed')
    print('RETAINED_VERIFY_PHASE filesystem', flush=True)
    objects = constructor.require_match(candidate, inventory, generated)
    if constructor.digest(objects) != built.get('filesystem_sha256'):
        raise ValueError('retained filesystem differs from final construction observation')
    relocation_verification = None
    if built.get('installation_relocation') is not None:
        relocation_verification = verify_relocations(candidate, constructor, inventory, initial,
            built, generated, objects, installation_policy)
    layout_verification = None
    if built.get('storage_layout') is not None:
        layout_policy, _ = read(rooted(root, '/tests/system-storage-layout-policy.json'))
        saved_layout, _ = read(rooted(root, output_name + '/storage-layout.json'))
        layout_verification = verify_constructed_layout(constructor, canonical, objects,
            layout_policy, saved_layout, built['storage_layout'])
    contract, _ = read(rooted(root, '/tests/database-contract.json'))
    policy, _ = read(rooted(root, '/tests/database-output-policy.json'))
    if accepted.get('contract_sha256') != constructor.digest(contract):
        raise ValueError('database contract differs from construction receipt')
    destination = database.validate_output_policy(policy)
    database_file = rooted(root, candidate_name + destination)
    print('RETAINED_VERIFY_PHASE package-database', flush=True)
    checked = database.payload.check(database_file, sqlite, contract, inventory)
    if (not checked['database_profile_verified'] or
            checked['database_sha256'] != accepted.get('database_sha256')):
        raise ValueError('installed database differs from accepted construction output')
    report = {'format': 1, 'scope': 'retained-builder-post-shutdown-consistency',
            'result': 'PASS', 'package_count': len(inventory['packages']),
            'object_count': len(objects), 'retained_record_sha256': retained_hash,
            'filesystem_sha256': constructor.digest(objects), 'inventory_sha256': inventory_hash,
            'database_verification': checked,
            'generation_authenticated': False, 'policy_approval_verified': False,
            'normal_boot_qualified': False,
            'state_review': reviewed_state(constructor, canonical, objects)}
    if relocation_verification is not None:
        report['construction_relocation'] = relocation_verification
    if layout_verification is not None:
        report['construction_storage_layout'] = layout_verification
    if storage_layout_policy is not None:
        report["storage_layout_review"] = reviewed_layout(
            constructor, canonical, objects, storage_layout_policy)
    if with_inventory:
        return report, objects, canonical
    return (report, objects) if with_observation else report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'helpers', 'sqlite', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--work-directory', required=True)
    parser.add_argument('--storage-layout-policy', type=Path)
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(args.root.resolve()) or args.output.exists() or args.output.is_symlink():
        parser.error('output must be new and outside the input artifact')
    try:
        report = verify(args.root, args.work_directory, args.helpers, args.sqlite,
                        storage_layout_policy=args.storage_layout_policy)
    except Exception as error:
        report = {'result': 'FAIL', 'scope': 'retained-builder-post-shutdown-consistency', 'error': str(error)}
        with args.output.open('x') as stream:
            json.dump(report, stream, indent=2); stream.write('\n')
        raise
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2); stream.write('\n')
    print('RETAINED_VERIFY_PASS packages=' + str(report['package_count']), flush=True)


if __name__ == '__main__':
    main()
