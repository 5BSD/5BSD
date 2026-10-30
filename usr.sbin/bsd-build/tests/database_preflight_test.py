#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Real SQLite preflight tests; synthetic schema contract, no generation approval."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

helper = os.environ.get('BSD_BUILD_DATABASE_PREFLIGHT_HELPER') or str(
    Path(__file__).resolve().parents[3] / 'tools/build/capimage/database_preflight.py')
spec = importlib.util.spec_from_file_location('database_preflight', helper)
preflight = importlib.util.module_from_spec(spec); spec.loader.exec_module(preflight)
SQLITE = None
SCHEMA = '''PRAGMA user_version=42;
CREATE TABLE packages(id INTEGER PRIMARY KEY,name TEXT,origin TEXT,version TEXT,arch TEXT,automatic INTEGER,locked INTEGER,vital INTEGER);
CREATE TABLE files(path TEXT PRIMARY KEY,package_id INTEGER REFERENCES packages(id));
CREATE TABLE deps(name TEXT,package_id INTEGER REFERENCES packages(id));
CREATE TABLE config_files(path TEXT,package_id INTEGER REFERENCES packages(id));
CREATE TABLE pkg_conflicts(package_id INTEGER REFERENCES packages(id),conflict_id INTEGER);
CREATE TABLE pkg_lock(exclusive INTEGER,advisory INTEGER,read INTEGER);
CREATE TABLE pkg_lock_pid(pid INTEGER PRIMARY KEY);
INSERT INTO packages VALUES(1,'fixture','tests/fixture','1','FreeBSD:16:amd64',0,0,1);
INSERT INTO files VALUES('/fixture',1);
INSERT INTO pkg_lock VALUES(0,0,0);
CREATE TABLE script(script_id INTEGER PRIMARY KEY,script TEXT);
CREATE TABLE pkg_script(package_id INTEGER REFERENCES packages(id),script_id INTEGER REFERENCES script(script_id));
CREATE TABLE lua_script(lua_script_id INTEGER PRIMARY KEY,lua_script TEXT);
CREATE TABLE pkg_lua_script(package_id INTEGER REFERENCES packages(id),lua_script_id INTEGER REFERENCES lua_script(lua_script_id));
CREATE TABLE option(option_id INTEGER PRIMARY KEY,option TEXT);
CREATE TABLE pkg_option(package_id INTEGER REFERENCES packages(id),option_id INTEGER REFERENCES option(option_id));
CREATE TABLE annotation(annotation_id INTEGER PRIMARY KEY,annotation TEXT);
CREATE TABLE pkg_annotation(package_id INTEGER REFERENCES packages(id),tag_id INTEGER REFERENCES annotation(annotation_id),value_id INTEGER REFERENCES annotation(annotation_id));
CREATE TABLE shlibs(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE directories(id INTEGER PRIMARY KEY,value TEXT);
CREATE TABLE pkg_directories(package_id INTEGER REFERENCES packages(id),directory_id INTEGER REFERENCES directories(id));
CREATE TABLE categories(id INTEGER PRIMARY KEY,value TEXT);
CREATE TABLE pkg_categories(package_id INTEGER REFERENCES packages(id),category_id INTEGER REFERENCES categories(id));
CREATE TABLE licenses(id INTEGER PRIMARY KEY,value TEXT);
CREATE TABLE pkg_licenses(package_id INTEGER REFERENCES packages(id),license_id INTEGER REFERENCES licenses(id));
CREATE TABLE users(id INTEGER PRIMARY KEY,value TEXT);
CREATE TABLE pkg_users(package_id INTEGER REFERENCES packages(id),user_id INTEGER REFERENCES users(id));
CREATE TABLE groups(id INTEGER PRIMARY KEY,value TEXT);
CREATE TABLE pkg_groups(package_id INTEGER REFERENCES packages(id),group_id INTEGER REFERENCES groups(id));
CREATE TABLE provides(id INTEGER PRIMARY KEY,value TEXT);
CREATE TABLE pkg_provides(package_id INTEGER REFERENCES packages(id),provide_id INTEGER REFERENCES provides(id));
CREATE TABLE requires(id INTEGER PRIMARY KEY,value TEXT);
CREATE TABLE pkg_requires(package_id INTEGER REFERENCES packages(id),require_id INTEGER REFERENCES requires(id));
CREATE TABLE pkg_shlibs_required(package_id INTEGER REFERENCES packages(id),shlib_id INTEGER REFERENCES shlibs(id));
CREATE TABLE pkg_shlibs_provided(package_id INTEGER REFERENCES packages(id),shlib_id INTEGER REFERENCES shlibs(id));
CREATE TABLE pkg_shlibs_required_ignore(package_id INTEGER REFERENCES packages(id),shlib_id INTEGER REFERENCES shlibs(id));
CREATE TABLE pkg_shlibs_provided_ignore(package_id INTEGER REFERENCES packages(id),shlib_id INTEGER REFERENCES shlibs(id));
'''


class DatabasePreflight(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.db = Path(self.workspace.name) / 'local.sqlite'
        self.sql(SCHEMA)
        self.contract = {'format': 1, 'scope': 'pkg-database-preflight-contract',
            'engine_sha256': 'a' * 64, 'schema_version': 42,
            'schema_sha256': preflight.digest(self.sql(preflight.SCHEMA_QUERY)),
            'packages': [{'name': 'fixture', 'origin': 'tests/fixture', 'version': '1',
                          'abi': 'FreeBSD:16:amd64', 'automatic': 0, 'locked': 0, 'vital': 1}]}

    def sql(self, sql):
        result = subprocess.run([str(SQLITE), '-batch', '-json', '-init', '/dev/null', str(self.db), sql],
            input='', capture_output=True, text=True, check=True)
        return json.loads(result.stdout) if result.stdout.strip() else []

    def check(self):
        return preflight.check(self.db, SQLITE, self.contract)

    def test_exact_policy_and_no_database_mutation(self):
        before = preflight.file_hash(self.db)
        result = self.check()
        self.assertEqual(result['result'], 'PASS')
        self.assertFalse(result['complete_archive_records_verified'])
        self.assertEqual(before, preflight.file_hash(self.db))

    def test_policy_changes_rejected(self):
        for column in ('automatic', 'locked', 'vital'):
            with self.subTest(column=column):
                self.sql('UPDATE packages SET ' + column + '=1-' + column)
                with self.assertRaisesRegex(ValueError, 'identities or installation policy'):
                    self.check()
                self.sql('UPDATE packages SET ' + column + '=1-' + column)

    def test_extra_schema_rejected(self):
        self.sql('CREATE TABLE unexpected(value TEXT)')
        with self.assertRaisesRegex(ValueError, 'schema differs'):
            self.check()

    def test_orphan_record_rejected(self):
        self.sql("INSERT INTO files VALUES('/orphan',2)")
        with self.assertRaisesRegex(ValueError, 'foreign-key'):
            self.check()

    def test_unowned_lookup_records_rejected(self):
        self.sql("INSERT INTO script VALUES(1,'unapproved hook')")
        with self.assertRaisesRegex(ValueError, 'unowned lookup records: script'):
            self.check()
        self.sql('INSERT INTO pkg_script VALUES(1,1)')
        self.assertEqual(self.check()['result'], 'PASS')

    def test_all_shlib_owners_and_annotation_roles_count(self):
        for table in ('pkg_shlibs_required', 'pkg_shlibs_provided',
                      'pkg_shlibs_required_ignore', 'pkg_shlibs_provided_ignore'):
            self.sql("INSERT INTO shlibs VALUES(1,'libfixture.so.1'); INSERT INTO " + table + " VALUES(1,1)")
            self.assertEqual(self.check()['result'], 'PASS')
            self.sql('DELETE FROM ' + table + '; DELETE FROM shlibs')
        self.sql("INSERT INTO annotation VALUES(1,'tag'),(2,'value'); INSERT INTO pkg_annotation VALUES(1,1,2)")
        self.assertEqual(self.check()['result'], 'PASS')
        self.sql("INSERT INTO annotation VALUES(3,'unowned')")
        with self.assertRaisesRegex(ValueError, 'unowned lookup records: annotation'):
            self.check()

    def test_null_owners_and_lookup_targets_rejected(self):
        self.sql("INSERT INTO files VALUES('/unowned',NULL)")
        self.assertEqual(self.sql('PRAGMA foreign_key_check'), [])
        with self.assertRaisesRegex(ValueError, 'no owning package: files'):
            self.check()
        self.sql("DELETE FROM files WHERE path='/unowned'; INSERT INTO pkg_script VALUES(1,NULL)")
        self.assertEqual(self.sql('PRAGMA foreign_key_check'), [])
        with self.assertRaisesRegex(ValueError, 'no lookup target: pkg_script.script_id'):
            self.check()

    def test_conflict_target_must_exist(self):
        self.sql('INSERT INTO pkg_conflicts VALUES(1,99)')
        self.assertEqual(self.sql('PRAGMA foreign_key_check'), [])
        with self.assertRaisesRegex(ValueError, 'conflict has no target'):
            self.check()

    def test_missing_package_rejected(self):
        self.sql('DELETE FROM files; DELETE FROM packages')
        with self.assertRaisesRegex(ValueError, 'identities or installation policy'):
            self.check()

    def test_lock_and_process_records_rejected(self):
        self.sql('UPDATE pkg_lock SET advisory=1')
        with self.assertRaisesRegex(ValueError, 'lock state'):
            self.check()
        self.sql('UPDATE pkg_lock SET advisory=0; INSERT INTO pkg_lock_pid VALUES(123)')
        with self.assertRaisesRegex(ValueError, 'process records'):
            self.check()

    def test_uncheckpointed_sidecar_rejected(self):
        Path(str(self.db) + '-wal').write_bytes(b'pending')
        with self.assertRaisesRegex(ValueError, 'sidecar'):
            self.check()

    def test_version_and_contract_ambiguity_rejected(self):
        self.sql('PRAGMA user_version=43')
        with self.assertRaisesRegex(ValueError, 'schema version mismatch'):
            self.check()
        self.contract['schema_version'] = 43
        with self.assertRaisesRegex(ValueError, 'unsupported pkg schema'):
            self.check()
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            preflight.decode('{"format":1,"format":1}')

    def test_symlink_database_rejected(self):
        link = Path(self.workspace.name) / 'alias'
        link.symlink_to(self.db)
        with self.assertRaisesRegex(ValueError, 'nonsymlink'):
            preflight.check(link, SQLITE, self.contract)

    def test_schema_1000_occurrence_constraints(self):
        self.sql('ALTER TABLE pkg_lua_script ADD COLUMN type INTEGER;'
                 'ALTER TABLE pkg_lua_script ADD COLUMN position INTEGER;'
                 'PRAGMA user_version=1000;'
                 "INSERT INTO lua_script VALUES(1,'A');"
                 'INSERT INTO pkg_lua_script VALUES(1,1,1,0),(1,1,1,1);')
        self.contract['schema_version'] = 1000
        self.contract['schema_sha256'] = preflight.digest(self.sql(preflight.SCHEMA_QUERY))
        self.assertEqual(self.check()['result'], 'PASS')
        for column, value, message in [('type', 'NULL', 'invalid Lua'),
                ('type', '7', 'invalid Lua'), ('type', '1.5', 'invalid Lua'),
                ('position', '-1', 'invalid Lua'), ('position', 'NULL', 'invalid Lua'),
                ('position', '1.5', 'invalid Lua'), ('position', '3', 'noncontiguous'),
                ('position', '0', 'noncontiguous')]:
            with self.subTest(column=column, value=value):
                before = self.db.read_bytes()
                self.sql('UPDATE pkg_lua_script SET '+column+'='+value+' WHERE rowid=2')
                with self.assertRaisesRegex(ValueError, message): self.check()
                self.db.write_bytes(before)


    def test_explicit_epoch_contract_and_tampering(self):
        self.sql('ALTER TABLE packages ADD COLUMN time INTEGER; UPDATE packages SET time=1700000000;')
        self.contract['schema_sha256'] = preflight.digest(self.sql(preflight.SCHEMA_QUERY))
        self.assertFalse(self.check()['installation_epoch_verified'])
        self.contract.update(format=2, install_epoch=1700000000)
        self.assertTrue(self.check()['installation_epoch_verified'])
        for value in ('1700000001', 'NULL'):
            self.sql('UPDATE packages SET time='+value)
            with self.assertRaisesRegex(ValueError,'timestamps differ'): self.check()

    def test_epoch_contract_bounds_and_missing_input(self):
        self.contract['format'] = 2
        with self.assertRaisesRegex(ValueError,'contract fields'): self.check()
        for value in (-1, 2**63, True, '1700000000', 1.5):
            with self.subTest(value=value):
                self.contract['install_epoch'] = value
                with self.assertRaisesRegex(ValueError,'installation epoch'): self.check()


    def test_archive_construction_profile_contract(self):
        self.contract.update(format=3, install_epoch=1700000000, schema_version=1000,
                             construction_profile='local-archive-registration-v1')
        self.assertEqual(preflight.validate_contract(self.contract), self.contract['packages'])
        self.contract['construction_profile'] = 'unreviewed'
        with self.assertRaisesRegex(ValueError, 'construction profile'): preflight.validate_contract(self.contract)
        self.contract['construction_profile'] = 'local-archive-registration-v1'
        self.contract['schema_version'] = 42
        with self.assertRaisesRegex(ValueError, 'construction profile'): preflight.validate_contract(self.contract)

    def test_archive_profile_requires_explicit_fields(self):
        self.contract.update(format=3, install_epoch=1700000000, schema_version=1000,
                             construction_profile='local-archive-registration-v1')
        for field in ('install_epoch', 'construction_profile', 'engine_sha256', 'schema_sha256'):
            original = self.contract.pop(field)
            with self.assertRaisesRegex(ValueError, 'contract fields'): preflight.validate_contract(self.contract)
            self.contract[field] = original



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--sqlite', type=Path, required=True)
    args, rest = parser.parse_known_args()
    SQLITE = args.sqlite.resolve(strict=True)
    unittest.main(argv=[__file__, *rest])
