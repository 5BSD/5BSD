#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compare pkg schema-42/1000 records with archive inventory.

Complements structural preflight. Does not yet verify all database tables,
authentication, or the installed filesystem.
"""
import argparse
import hashlib
import re
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import unquote_to_bytes


def sibling(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


preflight = sibling('database_preflight')
archive = sibling('package_inventory')
QUERIES = {
    'files': '''SELECT p.name AS package,f.path,f.sha256,f.uname,f.gname,
        f.perm,f.fflags,f.mtime,f.symlink_target FROM files f
        JOIN packages p ON p.id=f.package_id''',
    'directories': '''SELECT path,uname,gname,perm,fflags FROM directories''',
    'pkg_directories': '''SELECT p.name AS package,d.path,r.try
        FROM pkg_directories r JOIN directories d ON d.id=r.directory_id
        JOIN packages p ON p.id=r.package_id''',
    'deps': '''SELECT p.name AS package,d.name,d.origin,d.version FROM deps d
        JOIN packages p ON p.id=d.package_id''',
}


def metadata(path, value):
    attrs = {k: v for k, v in value.items() if k in ('uname', 'gname', 'perm', 'fflags')}
    normalized = archive.directory_attributes(path, attrs)
    if normalized.get('flags_clear', 0):
        raise ValueError('database flags require an explicit set mask: ' + path)
    return {'uname': attrs.get('uname'), 'gname': attrs.get('gname'),
            'perm': normalized.get('mode', 0), 'fflags': normalized.get('flags_set', 0)}


def expected_records(inventory):
    result = {name: [] for name in QUERIES}
    directories, names, files = {}, set(), set()
    for package in inventory['packages']:
        manifest = package['manifest']; name = manifest['name']
        if name != package['name'] or name in names:
            raise ValueError('duplicate or inconsistent inventory package name')
        names.add(name)
        for encoded, value in manifest.get('files', {}).items():
            path = archive.manifest_path(encoded)
            if path in files:
                raise ValueError('duplicate file ownership: ' + path)
            files.add(path)
            if isinstance(value, str):
                value = {'sum': value}
            if not isinstance(value, dict) or set(value) - {'sum', 'uname', 'gname', 'perm', 'fflags', 'mtime', 'symlink_target'}:
                raise ValueError('unsupported file record: ' + path)
            checksum = value.get('sum', '')
            mtime = value.get('mtime', 0)
            target = value.get('symlink_target')
            if not isinstance(checksum, str) or '\x00' in checksum or type(mtime) is not int:
                raise ValueError('invalid file checksum or timestamp: ' + path)
            if target is not None and (not isinstance(target, str) or '\x00' in target):
                raise ValueError('invalid file link target: ' + path)
            result['files'].append(dict(package=name, path=path, sha256=checksum,
                mtime=mtime, symlink_target=target, **metadata(path, value)))
        for encoded, attrs in manifest.get('directories', {}).items():
            path = archive.manifest_path(encoded)
            if not isinstance(attrs, dict):
                raise ValueError('explicit directory attributes required: ' + path)
            archive.directory_attributes(path, attrs)
            row = dict(path=path, **metadata(path, attrs))
            if path in directories and row != directories[path]:
                raise ValueError('conflicting database directory attributes: ' + path)
            directories[path] = row
            result['pkg_directories'].append({'package': name, 'path': path, 'try': 1})
        deps = manifest.get('deps', {})
        if not isinstance(deps, dict):
            raise ValueError('invalid inventory dependency map: ' + name)
        for dep, value in deps.items():
            if (not isinstance(value, dict) or set(value) != {'origin', 'version'} or
                    not all(isinstance(x, str) and x and '\x00' not in x
                            for x in (dep, value['origin'], value['version']))):
                raise ValueError('unsupported dependency record: ' + name)
            result['deps'].append(dict(package=name, name=dep, **value))
    result['directories'] = list(directories.values())
    return result


def ordered(rows):
    return sorted(json.dumps(row, sort_keys=True, separators=(',', ':')) for row in rows)


def check_records(query, inventory):
    expected = expected_records(inventory)
    for table, sql in QUERIES.items():
        actual = query(sql)
        if ordered(actual) != ordered(expected[table]):
            raise ValueError('database archive records differ: ' + table)
    return {name: len(rows) for name, rows in expected.items()}


# pkg script enum values include reserved slots 4 and 5. These are reviewed
# schema/engine semantics, not caller-supplied policy or positional guesses.
SHELL_PHASES = {'pre-install': 0, 'post-install': 1, 'pre-deinstall': 2,
                'post-deinstall': 3, 'install': 6, 'deinstall': 7}
LUA_PHASES = {name: value for name, value in SHELL_PHASES.items() if value < 4}


def check_hooks(query, inventory, schema_version):
    expected_shell, expected_lua = [], []
    for package in inventory['packages']:
        manifest = package['manifest']; name = manifest['name']
        for field, phases in (('scripts', SHELL_PHASES), ('lua_scripts', LUA_PHASES)):
            hooks = manifest.get(field, {})
            if not isinstance(hooks, dict) or set(hooks) - phases.keys():
                raise ValueError('unsupported hook phases: ' + name)
            for phase, scripts in hooks.items():
                if field == 'scripts':
                    if not isinstance(scripts, str):
                        raise ValueError('invalid shell hook body: ' + name)
                    body = unquote_to_bytes(scripts).decode('utf-8', errors='strict')
                    if '\x00' in body:
                        raise ValueError('NUL in shell hook body: ' + name)
                    expected_shell.append({'package': name, 'type': phases[phase], 'body': body})
                else:
                    if not isinstance(scripts, list):
                        raise ValueError('invalid Lua hook sequence: ' + name)
                    for position, body in enumerate(scripts):
                        if not isinstance(body, str) or '\x00' in body:
                            raise ValueError('invalid Lua hook body: ' + name)
                        expected_lua.append({'package': name, 'type': phases[phase],
                                             'position': position, 'body': body})
    actual_shell = query('SELECT p.name AS package,r.type,s.script AS body '
        'FROM pkg_script r JOIN script s ON s.script_id=r.script_id '
        'JOIN packages p ON p.id=r.package_id')
    if ordered(actual_shell) != ordered(expected_shell):
        raise ValueError('database archive records differ: shell hooks')
    if schema_version == 42:
        if expected_lua or query('SELECT package_id FROM pkg_lua_script'):
            raise ValueError('Lua occurrence verification requires schema 1000')
    elif schema_version == 1000:
        actual_lua = query('SELECT p.name AS package,r.type,r.position,s.lua_script AS body '
            'FROM pkg_lua_script r JOIN lua_script s ON s.lua_script_id=r.lua_script_id '
            'JOIN packages p ON p.id=r.package_id')
        if ordered(actual_lua) != ordered(expected_lua):
            raise ValueError('database archive records differ: Lua occurrences')
    else:
        raise ValueError('unsupported hook schema')
    return {'shell_hooks': len(expected_shell), 'lua_occurrences': len(expected_lua)}


# Fixed reviewed SQL mappings for schema fields; package/user values are never
# interpolated into SQL. All four library roles are independent declarations.
COLLECTIONS = {
    'categories': ('categories', 'id', 'name', 'pkg_categories', 'category_id'),
    'licenses': ('licenses', 'id', 'name', 'pkg_licenses', 'license_id'),
    'users': ('users', 'id', 'name', 'pkg_users', 'user_id'),
    'groups': ('groups', 'id', 'name', 'pkg_groups', 'group_id'),
    'provides': ('provides', 'id', 'provide', 'pkg_provides', 'provide_id'),
    'requires': ('requires', 'id', 'require', 'pkg_requires', 'require_id'),
}
for role in ('required', 'provided', 'required_ignore', 'provided_ignore'):
    COLLECTIONS['shlibs_' + role] = ('shlibs', 'id', 'name', 'pkg_shlibs_' + role, 'shlib_id')


def text_value(value):
    return isinstance(value, str) and '\x00' not in value


def check_collections(query, inventory):
    expected = {field: [] for field in (*COLLECTIONS, 'options', 'annotations')}
    for package in inventory['packages']:
        manifest = package['manifest']; name = manifest['name']
        for field in COLLECTIONS:
            values = manifest.get(field, [])
            if (not isinstance(values, list) or
                    any(not text_value(v) or not v for v in values) or
                    len(set(values)) != len(values)):
                raise ValueError('invalid manifest collection: ' + field)
            expected[field].extend({'package': name, 'value': value} for value in values)
        for field in ('options', 'annotations'):
            values = manifest.get(field, {})
            if not isinstance(values, dict):
                raise ValueError('invalid manifest map: ' + field)
            for key, value in values.items():
                if field == 'options' and type(value) is bool:
                    value = 'on' if value else 'off'
                if not text_value(key) or not key or not text_value(value):
                    raise ValueError('invalid manifest map entry: ' + field)
                expected[field].append({'package': name, 'key': key, 'value': value})
    for field, (table, key, value, relation, foreign) in COLLECTIONS.items():
        actual = query('SELECT p.name AS package,d."' + value + '" AS value FROM "' +
            relation + '" r JOIN "' + table + '" d ON d."' + key + '"=r."' + foreign +
            '" JOIN packages p ON p.id=r.package_id')
        if ordered(actual) != ordered(expected[field]):
            raise ValueError('database archive records differ: ' + field)
    maps = {
        'options': 'SELECT p.name AS package,d.option AS key,r.value FROM pkg_option r '
            'JOIN option d ON d.option_id=r.option_id JOIN packages p ON p.id=r.package_id',
        'annotations': 'SELECT p.name AS package,k.annotation AS key,v.annotation AS value '
            'FROM pkg_annotation r JOIN annotation k ON k.annotation_id=r.tag_id '
            'JOIN annotation v ON v.annotation_id=r.value_id JOIN packages p ON p.id=r.package_id',
    }
    for field, sql in maps.items():
        if ordered(query(sql)) != ordered(expected[field]):
            raise ValueError('database archive records differ: ' + field)
    return {field: len(rows) for field, rows in expected.items()}


def check_package_metadata(query, inventory):
    expected = []
    for package in inventory['packages']:
        manifest = package['manifest']; row = {'name': manifest['name']}
        for field in ('comment', 'desc', 'maintainer', 'www', 'prefix'):
            value = manifest.get(field)
            if field == 'www' and value is None:
                row[field] = None
                continue
            if not text_value(value):
                raise ValueError('invalid package metadata: ' + field)
            if field == 'desc':
                value = unquote_to_bytes(value).decode('utf-8', errors='strict')
                if '\x00' in value:
                    raise ValueError('NUL in package description')
            row[field] = value
        size = manifest.get('flatsize', 0)
        if type(size) is not int or not 0 <= size <= 2**63 - 1:
            raise ValueError('invalid package flat size')
        logic = manifest.get('licenselogic')
        if 'licenselogic' in manifest and (not isinstance(logic, str) or logic not in ('single', 'and', 'or')):
            raise ValueError('unsupported package license logic')
        formula = manifest.get('dep_formula')
        if formula is not None and not text_value(formula):
            raise ValueError('invalid package dependency formula')
        row.update(flatsize=size, licenselogic={None: 0, 'single': 1, 'and': 38, 'or': 124}[logic],
                   dep_formula=formula)
        expected.append(row)
    actual = query('SELECT name,comment,desc,maintainer,www,prefix,flatsize,licenselogic,dep_formula FROM packages')
    if ordered(actual) != ordered(expected):
        raise ValueError('database archive records differ: package metadata')
    return {'package_metadata': len(expected)}


def check_config_baselines(query, inventory):
    expected = []
    for package in inventory['packages']:
        manifest = package['manifest']
        declarations = manifest.get('config', [])
        if not isinstance(declarations, list):
            raise ValueError('invalid configuration declarations')
        paths = [archive.manifest_path(path) for path in declarations]
        if len(set(paths)) != len(paths) or package.get('config', []) != paths:
            raise ValueError('inconsistent configuration inventory')
        for path in paths:
            entry = package.get('entries', {}).get(path)
            if not isinstance(entry, dict) or entry.get('type') != 'file':
                raise ValueError('configuration baseline requires a regular archive payload: ' + path)
            size, digest = entry.get('size'), entry.get('sha256')
            if (type(size) is not int or size < 0 or not isinstance(digest, str) or
                    re.fullmatch('[0-9a-f]{64}', digest) is None):
                raise ValueError('invalid configuration archive digest or size: ' + path)
            expected.append(dict(package=manifest['name'], path=path, size=size, sha256=digest))
    actual = []
    # hex(blob) preserves exact bytes, including NUL and non-UTF8 bytes. SQL NULL
    # and an empty TEXT baseline must remain distinguishable. Never substitute
    # candidate filesystem contents for the original archive merge baseline.
    for row in query('SELECT p.name AS package,c.path,typeof(c.content) AS storage, '
                     'hex(CAST(c.content AS BLOB)) AS content FROM config_files c '
                     'JOIN packages p ON p.id=c.package_id'):
        if row['storage'] != 'text':
            raise ValueError('configuration baseline is missing or not text: ' + row['path'])
        content = bytes.fromhex(row['content'])
        actual.append(dict(package=row['package'], path=row['path'], size=len(content),
                           sha256=hashlib.sha256(content).hexdigest()))
    if ordered(actual) != ordered(expected):
        raise ValueError('database archive records differ: configuration baselines')
    return {'config_baselines': len(expected)}


def archive_messages(manifest):
    if 'messages' in manifest and 'message' in manifest:
        raise ValueError('ambiguous package message fields')
    value = manifest.get('messages', manifest.get('message', []))
    if isinstance(value, str):
        value = [{'message': value}]
    if not isinstance(value, list):
        raise ValueError('invalid package messages')
    result = []
    for message in value:
        if (not isinstance(message, dict) or 'message' not in message or
                set(message) - {'message', 'type', 'minimum_version', 'maximum_version'} or
                any(not text_value(v) for v in message.values())):
            raise ValueError('invalid package message record')
        phase = message.get('type')
        if phase is not None and phase not in ('install', 'remove', 'upgrade'):
            raise ValueError('unsupported package message type')
        if phase != 'upgrade' and any(k in message for k in ('minimum_version', 'maximum_version')):
            raise ValueError('version bounds on non-upgrade message')
        row = dict(message)
        # pkg_message_to_ucl trims ASCII whitespace; encoded percent sequences
        # in message bodies are literal and must not undergo path decoding.
        row['message'] = row['message'].strip(' \t\r\n\v\f')
        result.append(row)
    return result or None


def check_messages_and_conflicts(query, inventory):
    messages, conflicts = [], []
    for package in inventory['packages']:
        manifest = package['manifest']; name = manifest['name']
        messages.append(dict(name=name, message=archive_messages(manifest)))
        values = manifest.get('conflicts', [])
        if (not isinstance(values, list) or any(not text_value(v) or not v for v in values)
                or len(values) != len(set(values))):
            raise ValueError('invalid package conflicts')
        conflicts.extend(dict(package=name, conflict=value) for value in values)
    actual = query('SELECT name,message FROM packages')
    for row in actual:
        if row['message'] is not None:
            if not isinstance(row['message'], str):
                raise ValueError('invalid stored package messages')
            row['message'] = preflight.decode(row['message'].encode('utf-8'))
    if ordered(actual) != ordered(messages):
        raise ValueError('database archive records differ: messages')
    actual = query('SELECT p.name AS package,c.name AS conflict FROM pkg_conflicts r '
                   'JOIN packages p ON p.id=r.package_id JOIN packages c ON c.id=r.conflict_id')
    if ordered(actual) != ordered(conflicts):
        raise ValueError('database archive records differ: conflicts')
    return {'message_packages': sum(r['message'] is not None for r in messages),
            'conflicts': len(conflicts)}


def archive_solver_digest(manifest):
    # pkg 2.8.4 local-archive solver profile: complete manifest, version included,
    # scripts excluded, BLAKE2b-512, checksum version 2/type 2. This is a cache
    # identity, not an authentication hash or a signature over package contents.
    pairs = [(key, manifest[key]) for key in ('name', 'origin', 'version', 'arch')]
    vital = manifest.get('vital', False)
    if type(vital) is not bool:
        raise ValueError('invalid vital flag for solver digest')
    pairs.append(('vital', '1' if vital else '0'))
    for key, value in manifest.get('options', {}).items():
        pairs.append((key, ('on' if value else 'off') if type(value) is bool else value))
    for field, key in [('shlibs_required', 'required_shlib'), ('shlibs_provided', 'provided_shlib'),
                       ('users', 'user'), ('groups', 'group'), ('provides', 'provide'),
                       ('requires', 'require')]:
        pairs.extend((key, value) for value in manifest.get(field, []))
    for name, dep in manifest.get('deps', {}).items():
        pairs.append(('depend', name + '~' + dep['origin']))
    for path, attrs in manifest.get('files', {}).items():
        checksum = attrs if isinstance(attrs, str) else attrs.get('sum', '')
        pairs.append((archive.manifest_path(path), checksum))
    if any(not text_value(k) or not text_value(v) for k, v in pairs):
        raise ValueError('invalid solver digest input')
    encoded = sorted((k.encode('utf-8'), v.encode('utf-8')) for k, v in pairs)
    digest = hashlib.blake2b(b''.join(k + v for k, v in encoded)).digest()
    # pkg's base32 takes low bits first; RFC 4648's byte order is different.
    alphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769'
    number = int.from_bytes(digest, 'little')
    return '2$2$' + ''.join(alphabet[(number >> bit) & 31]
                           for bit in range(0, len(digest) * 8, 5))


def check_internal_package_fields(query, inventory):
    manifests = {p['manifest']['name']: p['manifest'] for p in inventory['packages']}
    rows = query('SELECT name,mtree_id,pkg_format_version,manifestdigest FROM packages')
    if len(rows) != len(manifests) or {r['name'] for r in rows} != set(manifests):
        raise ValueError('internal package identities differ')
    checked = absent = 0
    for row in rows:
        if row['mtree_id'] is not None or row['pkg_format_version'] is not None:
            raise ValueError('unsupported non-NULL reserved package field')
        if row['manifestdigest'] is None:
            # Direct registration does not populate the cache. No authenticated
            # identity is inferred from its absence, or from a matching cache.
            absent += 1
        elif row['manifestdigest'] != archive_solver_digest(manifests[row['name']]):
            raise ValueError('database archive records differ: solver digest')
        else:
            checked += 1
    return {'solver_digests': checked, 'absent_solver_digests': absent,
            'reserved_package_fields': len(rows)}


def reviewed_columns(schema_version):
    # Every column below is handled by structural preflight, control policy,
    # archive-record comparison, or the reviewed internal-cache rules. SQL IDs
    # are relational identities; their numeric allocation is not package data.
    columns = {
        'packages': 'id origin name version comment desc mtree_id message arch maintainer www prefix flatsize automatic locked licenselogic time manifestdigest pkg_format_version dep_formula vital',
        'files': 'path sha256 uname gname perm fflags mtime symlink_target package_id',
        'directories': 'id path uname gname perm fflags',
        'pkg_directories': 'package_id directory_id try',
        'deps': 'origin name version package_id',
        'config_files': 'path content package_id',
        'script': 'script_id script',
        'pkg_script': 'package_id type script_id',
        'lua_script': 'lua_script_id lua_script',
        'pkg_lua_script': 'package_id lua_script_id type',
        'option': 'option_id option',
        'pkg_option': 'package_id option_id value',
        'annotation': 'annotation_id annotation',
        'pkg_annotation': 'package_id tag_id value_id',
        'pkg_conflicts': 'package_id conflict_id',
        'pkg_lock': 'exclusive advisory read',
        'pkg_lock_pid': 'pid',
        'shlibs': 'id name',
        'provides': 'id provide',
        'requires': 'id require',
    }
    for table, foreign in [('categories', 'category'), ('licenses', 'license'),
                           ('users', 'user'), ('groups', 'group')]:
        columns[table] = 'id name'
        columns['pkg_' + table] = 'package_id ' + foreign + '_id'
    for role in ('required', 'provided', 'required_ignore', 'provided_ignore'):
        columns['pkg_shlibs_' + role] = 'package_id shlib_id'
    columns['pkg_provides'] = 'package_id provide_id'
    columns['pkg_requires'] = 'package_id require_id'
    if schema_version == 1000:
        columns['pkg_lua_script'] += ' position'
    elif schema_version != 42:
        raise ValueError('unreviewed database schema coverage')
    return {name: set(fields.split()) for name, fields in columns.items()}


def check_schema_coverage(query, schema_version):
    expected = reviewed_columns(schema_version)
    tables = query("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
    if [r['name'] for r in tables] != sorted(expected):
        raise ValueError('database tables differ from reviewed record coverage')
    for table, fields in expected.items():
        # table_xinfo includes generated/hidden columns; table_info can omit them.
        rows = query('PRAGMA table_xinfo("' + table + '")')
        if {r['name'] for r in rows} != fields or any(r['hidden'] != 0 for r in rows):
            raise ValueError('database columns differ from reviewed record coverage: ' + table)
    return {'schema_tables': len(expected),
            'schema_columns': sum(len(fields) for fields in expected.values())}


def check(database, sqlite, contract, inventory):
    result = preflight.check(database, sqlite, contract)
    identities = sorted((p['manifest']['name'], p['manifest']['origin'],
                         p['manifest']['version'], p['manifest']['abi'])
                        for p in inventory['packages'])
    policy = sorted(tuple(p[k] for k in ('name', 'origin', 'version', 'abi'))
                    for p in contract['packages'])
    if identities != policy:
        raise ValueError('archive inventory differs from selected package policy')
    database, sqlite = Path(database).resolve(strict=True), Path(sqlite).resolve(strict=True)
    def query(sql):
        return preflight.query_database(database, sqlite, sql)
    counts = check_schema_coverage(query, contract['schema_version'])
    counts.update(check_records(query, inventory))
    counts.update(check_hooks(query, inventory, contract['schema_version']))
    counts.update(check_collections(query, inventory))
    counts.update(check_package_metadata(query, inventory))
    counts.update(check_config_baselines(query, inventory))
    counts.update(check_messages_and_conflicts(query, inventory))
    counts.update(check_internal_package_fields(query, inventory))
    if contract['format'] == 3 and counts['solver_digests'] != len(identities):
        raise ValueError('construction profile requires populated archive solver digests')
    preflight.require_quiescent(database)
    if (preflight.file_hash(database) != result['database_sha256'] or
            preflight.file_hash(sqlite) != result['sqlite_sha256']):
        raise ValueError('database or query executable changed during record verification')
    result.update(scope='pkg-database-payload-records', verified_record_counts=counts,
                  inventory_sha256=preflight.digest(inventory),
                  database_profile_verified=contract['format'] == 3)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('database', 'sqlite', 'contract', 'inventory'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        result = check(args.database, args.sqlite,
            preflight.decode(args.contract.read_bytes()), preflight.decode(args.inventory.read_bytes()))
    except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'result': 'FAIL', 'scope': 'pkg-database-payload-records', 'error': str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
