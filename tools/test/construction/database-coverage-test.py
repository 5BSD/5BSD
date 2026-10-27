#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify record-coverage rejection using private copies of a real pkg database.

Negative cases deliberately update the test schema contract to prove that a schema
hash alone cannot authorize unreviewed record semantics. Never use those contracts
as production policy. Source database and supplied policy remain unchanged.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('database', 'sqlite', 'contract', 'inventory', 'helper', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    work = args.work.absolute()
    if not work.is_relative_to('/usr/obj/usr/src'):
        parser.error('work must be a new directory under /usr/obj/usr/src')
    work.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('payload', args.helper.resolve(strict=True))
    payload = importlib.util.module_from_spec(spec); spec.loader.exec_module(payload)
    database, sqlite = args.database.resolve(strict=True), args.sqlite.resolve(strict=True)
    payload.preflight.require_quiescent(database)
    contract = payload.preflight.decode(args.contract.read_bytes())
    inventory = payload.preflight.decode(args.inventory.read_bytes())
    inputs = [database, sqlite, args.contract, args.inventory, args.helper]
    hashes = {str(p): payload.preflight.file_hash(p) for p in inputs}
    report = {'result': 'RUNNING', 'scope': 'reviewed database record coverage',
              'production_contract_generated': False, 'cases': [], 'files_sha256': hashes}
    cases = [('baseline', None),
             ('extra-table', 'CREATE TABLE unexplained_policy(value TEXT)'),
             ('extra-column', 'ALTER TABLE packages ADD COLUMN unexplained_privilege INTEGER'),
             ('missing-column', 'ALTER TABLE packages DROP COLUMN mtree_id'),
             ('hidden-column', 'ALTER TABLE packages ADD COLUMN unexplained_generated INTEGER GENERATED ALWAYS AS (1) VIRTUAL')]
    try:
        for name, mutation in cases:
            target = work / (name + '.sqlite'); shutil.copyfile(database, target)
            policy = dict(contract)
            if mutation:
                subprocess.run([str(sqlite), '-batch', '-init', '/dev/null', str(target), mutation],
                    stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True, timeout=60)
                policy['schema_sha256'] = payload.preflight.digest(
                    payload.preflight.query_database(target, sqlite, payload.preflight.SCHEMA_QUERY))
            before = payload.preflight.file_hash(target)
            payload.preflight.check(target, sqlite, policy)
            try:
                result = payload.check(target, sqlite, policy, inventory)
            except ValueError as error:
                if mutation is None or 'reviewed record coverage' not in str(error):
                    raise
                report['cases'].append(dict(name=name, preflight='PASS',
                    result='EXPECTED_REJECTION', error=str(error)))
            else:
                if mutation is not None:
                    raise AssertionError('unreviewed schema accepted: ' + name)
                report['cases'].append(dict(name=name, preflight='PASS', result=result))
            if payload.preflight.file_hash(target) != before:
                raise AssertionError('verification changed database')
        report['result'] = 'PASS'
    except BaseException as error:
        report.update(result='FAIL', error=str(error))
        raise
    finally:
        for p in inputs:
            if payload.preflight.file_hash(p) != hashes[str(p)]:
                report.update(result='FAIL', error='input changed: ' + str(p))
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    if report['result'] != 'PASS':
        raise RuntimeError(report['error'])


if __name__ == '__main__':
    main()
