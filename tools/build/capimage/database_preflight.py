#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check a quiescent pkg database against explicit trusted-builder expectations.

This supplements archive-record verification; it does not replace it. The contract
must come from selected engine/schema and generation-policy inputs, never from the
candidate being approved. Inputs are not authenticated by this offline helper.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


SCHEMA_QUERY = 'SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name;'
CONTROL_FIELDS = ('name', 'origin', 'version', 'abi', 'automatic', 'locked', 'vital')

# Schema-42 dictionary tables and every relation that owns their rows. A newly
# constructed generation has no retired/unowned dictionary entries to retain.
LOOKUP_OWNERS = (
    ('script', 'script_id', (('pkg_script', 'script_id'),)),
    ('lua_script', 'lua_script_id', (('pkg_lua_script', 'lua_script_id'),)),
    ('option', 'option_id', (('pkg_option', 'option_id'),)),
    ('directories', 'id', (('pkg_directories', 'directory_id'),)),
    ('categories', 'id', (('pkg_categories', 'category_id'),)),
    ('licenses', 'id', (('pkg_licenses', 'license_id'),)),
    ('users', 'id', (('pkg_users', 'user_id'),)),
    ('groups', 'id', (('pkg_groups', 'group_id'),)),
    ('shlibs', 'id', (('pkg_shlibs_required', 'shlib_id'),
                    ('pkg_shlibs_provided', 'shlib_id'),
                    ('pkg_shlibs_required_ignore', 'shlib_id'),
                    ('pkg_shlibs_provided_ignore', 'shlib_id'))),
    ('annotation', 'annotation_id', (('pkg_annotation', 'tag_id'),
                                  ('pkg_annotation', 'value_id'))),
    ('provides', 'id', (('pkg_provides', 'provide_id'),)),
    ('requires', 'id', (('pkg_requires', 'require_id'),)),
)


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def decode(data):
    def invalid(value):
        raise ValueError('invalid JSON constant: ' + value)
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def digest(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()).hexdigest()


def file_hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_contract(value):
    keys = {'format', 'scope', 'engine_sha256', 'schema_version', 'schema_sha256', 'packages'}
    if isinstance(value, dict) and value.get('format') in (2, 3):
        keys.add('install_epoch')
    if isinstance(value, dict) and value.get('format') == 3:
        keys.add('construction_profile')
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError('invalid database preflight contract fields')
    if type(value['format']) is not int or value['format'] not in (1, 2, 3) or value['scope'] != 'pkg-database-preflight-contract':
        raise ValueError('unsupported database preflight contract')
    if value['format'] in (2, 3) and (type(value['install_epoch']) is not int or
            not 0 <= value['install_epoch'] <= 2**63 - 1):
        raise ValueError('invalid explicit installation epoch')
    if value['format'] == 3 and (value['construction_profile'] != 'local-archive-registration-v1' or
            type(value['schema_version']) is not int or value['schema_version'] != 1000):
        raise ValueError('unsupported database construction profile or schema')
    # Schemas 42 and 1000 share control/lifecycle tables; 1000 adds ordered Lua occurrences.
    # New engine schemas require review, not merely a caller-supplied digest.
    if type(value['schema_version']) is not int or value['schema_version'] not in (42, 1000):
        raise ValueError('unsupported pkg schema version')
    for field in ('engine_sha256', 'schema_sha256'):
        if not isinstance(value[field], str) or not re.fullmatch('[0-9a-f]{64}', value[field]):
            raise ValueError('invalid contract digest: ' + field)
    rows = value['packages']
    if not isinstance(rows, list) or not rows:
        raise ValueError('empty or invalid selected package policy')
    names = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != set(CONTROL_FIELDS):
            raise ValueError('invalid package policy fields')
        for field in CONTROL_FIELDS[:4]:
            if not isinstance(row[field], str) or not row[field] or '\x00' in row[field]:
                raise ValueError('invalid package identity: ' + field)
        for field in CONTROL_FIELDS[4:]:
            if type(row[field]) is not int or row[field] not in (0, 1):
                raise ValueError('package policy must explicitly specify 0 or 1: ' + field)
        if row['name'] in names:
            raise ValueError('duplicate selected package policy')
        names.add(row['name'])
    return sorted(rows, key=lambda row: row['name'])


def query_database(database, sqlite, sql):
    # immutable avoids creating or updating shared-memory/WAL files. Only use
    # on quiescent trusted-builder inputs; hashes do not make live races safe.
    uri = database.as_uri() + '?mode=ro&immutable=1'
    result = subprocess.run([str(sqlite), '-batch', '-json', '-readonly',
        '-init', '/dev/null', uri, 'PRAGMA trusted_schema=OFF; ' + sql],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
        env={'PATH': '/bin:/usr/bin', 'HOME': '/nonexistent', 'LC_ALL': 'C'})
    if result.returncode or result.stderr:
        raise ValueError('database query failed: ' + result.stderr.strip())
    return decode(result.stdout) if result.stdout.strip() else []



def require_quiescent(database):
    for suffix in ('-wal', '-journal'):
        sidecar = Path(str(database) + suffix)
        if sidecar.is_symlink() or (sidecar.exists() and (not sidecar.is_file() or sidecar.stat().st_size)):
            raise ValueError('database has an uncheckpointed or unsafe sidecar: ' + suffix)


def check(database, sqlite, contract):
    expected = validate_contract(contract)
    database, sqlite = Path(database), Path(sqlite)
    if database.is_symlink() or not database.is_file():
        raise ValueError('requires a regular, nonsymlink database')
    database = database.resolve(strict=True)
    sqlite = sqlite.resolve(strict=True)

    require_quiescent(database)
    before = file_hash(database)
    engine_tool = file_hash(sqlite)

    def query(sql):
        return query_database(database, sqlite, sql)

    if query('PRAGMA user_version;') != [{'user_version': contract['schema_version']}]:
        raise ValueError('database schema version mismatch')
    if digest(query(SCHEMA_QUERY)) != contract['schema_sha256']:
        raise ValueError('database schema differs from selected engine contract')
    if query('PRAGMA integrity_check;') != [{'integrity_check': 'ok'}]:
        raise ValueError('database structural integrity failure')
    if query('PRAGMA foreign_key_check;'):
        raise ValueError('database contains invalid foreign-key relationships')
    # pkg schema 42 calls this column arch but stores pkg->abi (or altabi).
    columns = ','.join('arch AS abi' if field == 'abi' else field for field in CONTROL_FIELDS)
    owned_tables = {'files', 'deps', 'config_files', 'pkg_conflicts'}
    owned_tables.update(relation for _, _, owners in LOOKUP_OWNERS for relation, _ in owners)
    for table in sorted(owned_tables):
        if query('SELECT count(*) AS count FROM "' + table + '" WHERE NOT EXISTS '
                 '(SELECT 1 FROM packages WHERE packages.id="' + table + '".package_id);') != [{'count': 0}]:
            raise ValueError('database record has no owning package: ' + table)
    if query('SELECT count(*) AS count FROM pkg_conflicts WHERE NOT EXISTS '
             '(SELECT 1 FROM packages WHERE packages.id=pkg_conflicts.conflict_id);') != [{'count': 0}]:
        raise ValueError('database conflict has no target package')
    for table, key, owners in LOOKUP_OWNERS:
        for relation, column in owners:
            if query('SELECT count(*) AS count FROM "' + relation + '" WHERE NOT EXISTS '
                     '(SELECT 1 FROM "' + table + '" WHERE "' + table + '"."' + key +
                     '"="' + relation + '"."' + column + '");') != [{'count': 0}]:
                raise ValueError('database relation has no lookup target: ' + relation + '.' + column)
        predicates = ['NOT EXISTS (SELECT 1 FROM "' + relation + '" WHERE "' +
                      relation + '"."' + column + '"="' + table + '"."' + key + '")'
                      for relation, column in owners]
        rows = query('SELECT count(*) AS count FROM "' + table + '" WHERE ' +
                     ' AND '.join(predicates) + ';')
        if rows != [{'count': 0}]:
            raise ValueError('database retains unowned lookup records: ' + table)
    if contract['schema_version'] == 1000:
        if query("SELECT count(*) AS count FROM pkg_lua_script WHERE "
                 "typeof(type) != 'integer' OR type NOT BETWEEN 0 AND 3 OR "
                 "typeof(position) != 'integer' OR position < 0;") != [{'count': 0}]:
            raise ValueError('database has invalid Lua occurrence phase or position')
        if query('SELECT package_id,type FROM pkg_lua_script GROUP BY package_id,type '
                 'HAVING min(position) != 0 OR max(position)+1 != count(*) '
                 'OR count(DISTINCT position) != count(*);'):
            raise ValueError('database has noncontiguous Lua occurrence positions')
    actual = query('SELECT ' + columns + ' FROM packages ORDER BY name;')
    if actual != expected:
        raise ValueError('database package identities or installation policy differ')
    if contract['format'] in (2, 3):
        times = query('SELECT name,time FROM packages ORDER BY name;')
        wanted = [{'name': row['name'], 'time': contract['install_epoch']} for row in expected]
        if times != wanted:
            raise ValueError('database installation timestamps differ from explicit epoch')
    if query('SELECT exclusive,advisory,read FROM pkg_lock;') != [{'exclusive': 0, 'advisory': 0, 'read': 0}]:
        raise ValueError('database lock state is not quiescent')
    if query('SELECT pid FROM pkg_lock_pid;'):
        raise ValueError('database retains lock process records')
    require_quiescent(database)
    if file_hash(database) != before or file_hash(sqlite) != engine_tool:
        raise ValueError('database or query executable changed during preflight')
    return {'format': 1, 'scope': 'pkg-database-preflight', 'result': 'PASS',
            'database_sha256': before, 'contract_sha256': digest(contract),
            'sqlite_sha256': engine_tool, 'selected_engine_sha256': contract['engine_sha256'],
            'package_count': len(expected), 'installation_epoch_verified': contract['format'] in (2, 3), 'inputs_authenticated': False,
            'complete_archive_records_verified': False, 'generation_authenticated': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--sqlite', type=Path, required=True)
    parser.add_argument('--contract', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = check(args.database, args.sqlite, decode(args.contract.read_bytes()))
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'scope': 'pkg-database-preflight', 'result': 'FAIL', 'error': str(error)}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
