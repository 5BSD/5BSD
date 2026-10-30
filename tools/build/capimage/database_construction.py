#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Construct and verify a fresh package database in an offline builder jail.

The builder/kernel and explicit tools are trusted. This helper does not authenticate
inputs, modify an installed system, apply BIP, or authorize generation activation.
"""
import argparse
import copy
import json
import importlib.util
from pathlib import Path
import os
import shutil
import subprocess
import sys

spec = importlib.util.spec_from_file_location('database_payload', Path(__file__).with_name('database_payload.py'))
payload = importlib.util.module_from_spec(spec); spec.loader.exec_module(payload)

construction = payload.sibling('construction')
closure = payload.sibling('package_closure')


def prepare(pkg, sqlite, inventory_record, contract, osversion):
    payload.preflight.validate_contract(contract)
    if contract['format'] != 3:
        raise ValueError('database construction requires a format-3 profile')
    if type(osversion) is not int or not 0 < osversion <= 2**31 - 1:
        raise ValueError('explicit positive 32-bit target OSVERSION required')
    pkg, sqlite = Path(pkg).resolve(strict=True), Path(sqlite).resolve(strict=True)
    if payload.preflight.file_hash(pkg) != contract['engine_sha256']:
        raise ValueError('selected pkg executable differs from construction contract')
    dynamic = subprocess.run(['readelf', '-d', str(pkg)], capture_output=True,
                             text=True, check=True, timeout=30)
    if '(NEEDED)' in dynamic.stdout:
        raise ValueError('construction requires an explicit static pkg executable')
    inventory = construction.inventory_from_archives(inventory_record)
    manifests = {p['name']: p['manifest'] for p in inventory['packages']}
    if len(manifests) != len(inventory['packages']):
        raise ValueError('duplicate selected package name')
    policy = {p['name']: p for p in contract['packages']}
    if set(policy) != set(manifests):
        raise ValueError('archive set differs from selected package policy')
    abis = set()
    for name, manifest in manifests.items():
        row = policy[name]
        if any(row[k] != manifest[k] for k in ('name', 'origin', 'version', 'abi')):
            raise ValueError('archive identity differs from policy: ' + name)
        if row['automatic'] != 0 or row['locked'] != 0 or row['vital'] != int(manifest.get('vital', False)):
            raise ValueError('unsupported initial package control policy: ' + name)
        abis.add(row['abi'])
        for dependency, expected in manifest.get('deps', {}).items():
            target = manifests.get(dependency)
            # Recorded dependency versions are build metadata, not exact pins.
            # Selected archive versions remain bound to the contract above.
            if target is None or target['origin'] != expected['origin']:
                raise ValueError('selected dependency identity mismatch: ' + name + ': ' + dependency)
        if any(conflict in manifests for conflict in manifest.get('conflicts', [])):
            raise ValueError('selected archives declare a package conflict: ' + name)
    if len(abis) != 1:
        raise ValueError('construction requires a single target ABI')
    closure.require_shared_libraries(manifests.values())
    return pkg, sqlite, inventory, abis.pop()


def construct(pkg, sqlite, inventory, contract, abi, osversion, work, timeout, progress=None):
    if os.geteuid() != 0:
        raise PermissionError('database construction requires root for a private jail; use a disposable builder VM')
    if work.is_symlink() or work.exists():
        raise ValueError('construction work directory must be new')
    work.mkdir(mode=0o700)
    root = work / 'root'; root.mkdir(mode=0o700)
    for path in ('inputs', 'repos', 'etc', 'var/db/pkg', 'var/cache/pkg'):
        (root / path).mkdir(parents=True, exist_ok=True)
    (root / 'inputs/pkg.conf').write_text('')
    if progress: progress('database-stage-inputs')
    selected = []
    for index, package in enumerate(inventory['packages']):
        target = root / 'inputs' / (str(index) + '.pkg')
        shutil.copyfile(package['archive'], target)
        target.chmod(0o444)
        if payload.preflight.file_hash(target) != package['archive_sha256']:
            raise ValueError('copied archive differs from verified input')
        selected.append('/inputs/' + target.name)
    hashes = {str(pkg): contract['engine_sha256'], str(sqlite): payload.preflight.file_hash(sqlite)}
    for package in inventory['packages']:
        hashes[package['archive']] = package['archive_sha256']
    argv = ['-C', '/inputs/pkg.conf', '-R', '/repos']
    for option in ['ABI=' + abi, 'OSVERSION=' + str(osversion), 'PKG_DBDIR=/var/db/pkg',
                   'PKG_CACHEDIR=/var/cache/pkg', 'PKG_ENABLE_PLUGINS=no', 'PKG_TRIGGERS_ENABLE=no',
                   'RUN_SCRIPTS=no', 'REPO_AUTOUPDATE=no', 'SYSLOG=no', 'INSTALL_AS_USER=yes']:
        argv.extend(['-o', option])
    argv.extend(['install', '--register-only', '--local-only', '--yes', *selected])
    report = dict(format=1, scope='trusted-builder-database-construction', result='RUNNING',
                  inputs_authenticated=False, generation_authenticated=False,
                  contract_sha256=payload.preflight.digest(contract),
                  inventory_sha256=payload.preflight.digest(inventory), files_sha256=hashes,
                  abi=abi, osversion=osversion, argv=argv, timeout_seconds=timeout,
                  jail_parameters=construction.JAIL_PARAMETERS)
    construction.write_record(work / 'construction.json', report)
    try:
        for name, expected in hashes.items():
            if payload.preflight.file_hash(Path(name)) != expected:
                raise ValueError('construction input changed before execution: ' + name)
        if progress: progress('database-register')
        with construction.private_jail(root) as jid:
            with (work / 'registration.log').open('xb') as log:
                subprocess.run([str(pkg), '-j', jid, *argv], check=True,
                    env=dict(construction.ENVIRONMENT, PKG_INSTALL_EPOCH=str(contract['install_epoch'])),
                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                    close_fds=True, umask=0o022, timeout=timeout)
        database = root / 'var/db/pkg/local.sqlite'
        if progress: progress('database-verify-records')
        verification = payload.check(database, sqlite, contract, inventory)
        if progress: progress('database-recheck-inputs')
        for name, expected in hashes.items():
            if payload.preflight.file_hash(Path(name)) != expected:
                raise ValueError('construction input changed: ' + name)
        for index, package in enumerate(inventory['packages']):
            if payload.preflight.file_hash(root / 'inputs' / (str(index) + '.pkg')) != package['archive_sha256']:
                raise ValueError('jailed archive input changed')
        if progress: progress('database-accept-output')
        accepted = work / 'local.sqlite'
        shutil.copyfile(database, accepted); accepted.chmod(0o600)
        if payload.preflight.file_hash(accepted) != verification['database_sha256']:
            raise ValueError('accepted database copy differs from verified output')
        report.update(result='PASS', verification=verification,
                      database_sha256=verification['database_sha256'])
        construction.write_record(work / 'receipt.json', report)
        construction.write_record(work / 'construction.json', report)
        return report
    except BaseException as error:
        (work / 'receipt.json').unlink(missing_ok=True)
        (work / 'local.sqlite').unlink(missing_ok=True)
        report.update(result='FAIL', error=str(error))
        construction.write_record(work / 'construction.json', report)
        raise


def validate_output_policy(policy):
    if not isinstance(policy, dict) or set(policy) != {'path', 'uid', 'gid', 'mode', 'flags_set'}:
        raise ValueError('explicit database output path and metadata required')
    path = policy['path']
    if not isinstance(path, str) or path == '/' or payload.archive.canonical_path(path) != path:
        raise ValueError('invalid database output pathname')
    for key, maximum in [('uid', 2**32 - 2), ('gid', 2**32 - 2), ('mode', 0o7777), ('flags_set', 2**32 - 1)]:
        if type(policy[key]) is not int or not 0 <= policy[key] <= maximum:
            raise ValueError('invalid database output metadata: ' + key)
    return path


def install(root, inventory, generated, accepted_dir, contract, sqlite, policy, progress=None):
    path = validate_output_policy(policy)
    if progress: progress('database-install-reconcile-inputs')
    before = construction.require_match(root, inventory, generated)
    if path in before or path in generated['entries']:
        raise ValueError('fresh database output already exists or is preapproved')
    parent = str(Path(path).parent)
    if before.get(parent, {}).get('type') != 'directory':
        raise ValueError('database output parent is not a verified directory')
    receipt = payload.preflight.decode((accepted_dir / 'receipt.json').read_bytes())
    if (receipt.get('scope') != 'trusted-builder-database-construction' or receipt.get('result') != 'PASS' or
            receipt.get('contract_sha256') != payload.preflight.digest(contract) or
            receipt.get('inventory_sha256') != payload.preflight.digest(inventory)):
        raise ValueError('database receipt does not match selected construction inputs')
    source = accepted_dir / 'local.sqlite'
    if progress: progress('database-install-verify-records')
    verification = payload.check(source, sqlite, contract, inventory)
    if not verification['database_profile_verified'] or receipt.get('database_sha256') != verification['database_sha256']:
        raise ValueError('database receipt does not match accepted artifact')
    # Use the verified parent descriptor and exclusive creation. A candidate
    # symlink must never redirect this write or replace an existing database.
    directory = construction.open_object(root, parent, directory=True)
    try:
        fd = os.open(Path(path).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as output, source.open('rb') as stream:
            shutil.copyfileobj(stream, output)
            output.flush(); os.fsync(output.fileno())
    finally:
        os.close(directory)
    action = {'outputs': {path: dict(type='file', uid=policy['uid'], gid=policy['gid'],
                mode=policy['mode'], flags_set=policy['flags_set'], replace=False)}}
    if progress: progress('database-install-scan-output')
    raw_after = construction.generation.scan(root)
    if raw_after.get(path, {}).get('sha256') != verification['database_sha256']:
        raise ValueError('installed database differs from accepted artifact')
    construction.finalize_outputs(root, action, before, raw_after)
    if progress: progress('database-install-scan-finalized')
    after = construction.generation.scan(root)
    records = construction.output_records(action, after)
    installation = dict(scope='database-generation-installation',
        database_receipt_sha256=payload.preflight.digest(receipt), output_policy=policy,
        before_sha256=construction.digest(before), after_sha256=construction.digest(after),
        outputs=records, inputs_authenticated=False, generation_authenticated=False)
    sha256 = construction.digest(installation)
    updated = copy.deepcopy(generated)
    updated['entries'][path] = dict(records[path], source='database installation receipt sha256:' + sha256)
    if progress: progress('database-install-reconcile-finalized')
    construction.require_match(root, inventory, updated)
    return updated, dict(installation, sha256=sha256)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('pkg', 'sqlite', 'inventory', 'contract', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--osversion', type=int, required=True)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--plan', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.timeout <= 86400:
        parser.error('timeout must be between 1 and 86400 seconds')
    contract = payload.preflight.decode(args.contract.read_bytes())
    record = payload.preflight.decode(args.inventory.read_bytes())
    pkg, sqlite, inventory, abi = prepare(args.pkg, args.sqlite, record, contract, args.osversion)
    work = args.work.absolute()
    if work.exists() or work.is_symlink():
        raise ValueError('work must be new')
    if args.plan:
        print(json.dumps(dict(scope='trusted-builder-database-plan', package_count=len(inventory['packages']),
            abi=abi, osversion=args.osversion, engine_sha256=contract['engine_sha256'],
            inputs_authenticated=False, activation_authorized=False)))
        return
    print(json.dumps(construct(pkg, sqlite, inventory, contract, abi, args.osversion, work, args.timeout)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(result='FAIL', scope='trusted-builder-database-construction', error=str(error))), file=sys.stderr)
        sys.exit(1)
