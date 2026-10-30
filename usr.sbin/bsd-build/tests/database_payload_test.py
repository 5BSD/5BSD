#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Real SQLite payload record comparisons with independent manifest fixtures."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

helper = os.environ.get('BSD_BUILD_DATABASE_PAYLOAD_HELPER') or str(
    Path(__file__).resolve().parents[3] / 'tools/build/capimage/database_payload.py')
spec = importlib.util.spec_from_file_location('database_payload', helper)
payload = importlib.util.module_from_spec(spec); spec.loader.exec_module(payload)
SQLITE = None
SCHEMA = '''
CREATE TABLE packages(id INTEGER PRIMARY KEY,name TEXT);
INSERT INTO packages VALUES(1,'fixture'),(2,'shared');
CREATE TABLE files(path TEXT PRIMARY KEY,sha256 TEXT,uname TEXT,gname TEXT,perm INTEGER,fflags INTEGER,mtime INTEGER,symlink_target TEXT,package_id INTEGER);
INSERT INTO files VALUES('/file space','checksum','root','wheel',420,0,123,NULL,1);
INSERT INTO files VALUES('/alias','linksum','root','wheel',493,0,124,'/file space',1);
CREATE TABLE directories(id INTEGER PRIMARY KEY,path TEXT,uname TEXT,gname TEXT,perm INTEGER,fflags INTEGER);
INSERT INTO directories VALUES(1,'/dir','root','wheel',493,0);
CREATE TABLE pkg_directories(package_id INTEGER,directory_id INTEGER,try INTEGER);
INSERT INTO pkg_directories VALUES(1,1,1),(2,1,1);
CREATE TABLE deps(origin TEXT,name TEXT,version TEXT,package_id INTEGER);
INSERT INTO deps VALUES('test/shared','shared','1',1);
'''
INVENTORY = {'packages': [
    {'name': 'fixture', 'manifest': {'name': 'fixture',
     'files': {'/file%20space': {'sum': 'checksum', 'uname': 'root', 'gname': 'wheel', 'perm': '0644', 'mtime': 123},
               '/alias': {'sum': 'linksum', 'uname': 'root', 'gname': 'wheel', 'perm': '0755', 'mtime': 124, 'symlink_target': '/file space'}},
     'directories': {'/dir': {'uname': 'root', 'gname': 'wheel', 'perm': '0755'}},
     'deps': {'shared': {'origin': 'test/shared', 'version': '1'}}}},
    {'name': 'shared', 'manifest': {'name': 'shared',
     'directories': {'/dir': {'uname': 'root', 'gname': 'wheel', 'perm': '0755'}}}},
]}


class Records(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / 'db'
        self.sql(SCHEMA)
        self.inventory = copy.deepcopy(INVENTORY)

    def sql(self, sql):
        result = subprocess.run([str(SQLITE), '-batch', '-json', '-init', '/dev/null', str(self.db), sql],
            input='', capture_output=True, text=True, check=True)
        return json.loads(result.stdout) if result.stdout.strip() else []

    def check(self):
        return payload.check_records(lambda s: payload.preflight.query_database(self.db, SQLITE, s), self.inventory)

    def test_baseline_shared_directory_and_encoded_path(self):
        before = self.db.read_bytes()
        self.assertEqual(self.check(), {'files': 2, 'directories': 1, 'pkg_directories': 2, 'deps': 1})
        self.assertEqual(self.db.read_bytes(), before)

    def test_each_file_field(self):
        changes = {'sha256': "'other'", 'uname': "'nobody'", 'gname': "'other'", 'perm': '511',
                   'fflags': '2', 'mtime': '125', 'symlink_target': "'/other'", 'package_id': '2', 'path': "'/moved'"}
        for field, value in changes.items():
            with self.subTest(field=field):
                self.sql('BEGIN; UPDATE files SET ' + field + '=' + value + " WHERE path='/alias'; COMMIT;")
                with self.assertRaisesRegex(ValueError, 'differ: files'): self.check()
                self.sql('DELETE FROM files; INSERT INTO files VALUES' +
                    "('/file space','checksum','root','wheel',420,0,123,NULL,1)," +
                    "('/alias','linksum','root','wheel',493,0,124,'/file space',1);")

    def test_missing_and_extra_files(self):
        self.sql("DELETE FROM files WHERE path='/alias'")
        with self.assertRaisesRegex(ValueError, 'differ: files'): self.check()
        self.sql("INSERT INTO files VALUES('/alias','linksum','root','wheel',493,0,124,'/file space',1);")
        self.sql("INSERT INTO files SELECT '/extra',sha256,uname,gname,perm,fflags,mtime,symlink_target,package_id FROM files LIMIT 1")
        with self.assertRaisesRegex(ValueError, 'differ: files'): self.check()

    def test_directory_metadata(self):
        for field, value in [('uname', "'nobody'"), ('gname', "'other'"), ('perm', '511'), ('fflags', '2'), ('path', "'/other'")]:
            with self.subTest(field=field):
                before = self.db.read_bytes()
                self.sql('UPDATE directories SET ' + field + '=' + value)
                with self.assertRaisesRegex(ValueError, 'differ: directories'): self.check()
                self.db.write_bytes(before)

    def test_directory_ownership_and_try(self):
        for sql in ['DELETE FROM pkg_directories WHERE package_id=2',
                    'UPDATE pkg_directories SET try=0',
                    'INSERT INTO pkg_directories VALUES(1,1,1)']:
            with self.subTest(sql=sql):
                before = self.db.read_bytes(); self.sql(sql)
                with self.assertRaisesRegex(ValueError, 'differ: pkg_directories'): self.check()
                self.db.write_bytes(before)

    def test_dependency_identity_and_duplicates(self):
        for sql in ["UPDATE deps SET version='2'", "UPDATE deps SET origin='other'",
                    "UPDATE deps SET name='other'", 'UPDATE deps SET package_id=2',
                    'DELETE FROM deps', 'INSERT INTO deps SELECT * FROM deps']:
            with self.subTest(sql=sql):
                before = self.db.read_bytes(); self.sql(sql)
                with self.assertRaisesRegex(ValueError, 'differ: deps'): self.check()
                self.db.write_bytes(before)

    def test_null_is_not_empty_string(self):
        self.sql("UPDATE files SET symlink_target='' WHERE path='/file space'")
        with self.assertRaisesRegex(ValueError, 'differ: files'): self.check()

    def test_conflicting_shared_directory(self):
        self.inventory['packages'][1]['manifest']['directories']['/dir']['perm'] = '0777'
        with self.assertRaisesRegex(ValueError, 'conflicting database directory'): self.check()

    def test_unknown_file_attribute(self):
        self.inventory['packages'][0]['manifest']['files']['/alias']['unexpected'] = True
        with self.assertRaisesRegex(ValueError, 'unsupported file record'): self.check()

    def test_flag_semantics(self):
        self.inventory['packages'][0]['manifest']['files']['/alias']['fflags'] = 'schg'
        self.sql("UPDATE files SET fflags=131072 WHERE path='/alias'")
        self.check()

    def hook_fixture(self):
        self.sql("CREATE TABLE script(script_id INTEGER PRIMARY KEY,script TEXT);"
                 "CREATE TABLE pkg_script(package_id INTEGER,type INTEGER,script_id INTEGER);"
                 "INSERT INTO script VALUES(1,'echo 100%');"
                 "INSERT INTO pkg_script VALUES(1,6,1);"
                 "CREATE TABLE lua_script(lua_script_id INTEGER PRIMARY KEY,lua_script TEXT);"
                 "CREATE TABLE pkg_lua_script(package_id INTEGER,type INTEGER,position INTEGER,lua_script_id INTEGER);"
                 "INSERT INTO lua_script VALUES(1,'A'),(2,'B');"
                 "INSERT INTO pkg_lua_script VALUES(1,0,0,1),(1,1,0,1),(1,1,1,2),(1,1,2,1);")
        m = self.inventory['packages'][0]['manifest']
        m['scripts'] = {'install': 'echo 100%25'}
        m['lua_scripts'] = {'pre-install': ['A'], 'post-install': ['A', 'B', 'A']}

    def hooks(self, schema=1000):
        return payload.check_hooks(lambda s: payload.preflight.query_database(self.db, SQLITE, s), self.inventory, schema)

    def test_hook_phase_order_and_repetition(self):
        self.hook_fixture()
        self.assertEqual(self.hooks(), {'shell_hooks': 1, 'lua_occurrences': 4})

    def test_hook_mutations(self):
        self.hook_fixture()
        for statement, field in [
            ("UPDATE script SET script='other'", 'shell hooks'),
            ('UPDATE pkg_script SET type=7', 'shell hooks'),
            ('UPDATE pkg_script SET package_id=2', 'shell hooks'),
            ("UPDATE lua_script SET lua_script='other' WHERE lua_script_id=2", 'Lua occurrences'),
            ('UPDATE pkg_lua_script SET type=3 WHERE type=0', 'Lua occurrences'),
            ('UPDATE pkg_lua_script SET position=3 WHERE type=1 AND position=2', 'Lua occurrences'),
            ('UPDATE pkg_lua_script SET lua_script_id=3-lua_script_id WHERE type=1 AND position<2', 'Lua occurrences'),
            ('DELETE FROM pkg_lua_script WHERE type=1 AND position=2', 'Lua occurrences'),
            ('INSERT INTO pkg_lua_script VALUES(1,1,3,1)', 'Lua occurrences'),
            ('UPDATE pkg_lua_script SET package_id=2', 'Lua occurrences')]:
            with self.subTest(statement=statement):
                before = self.db.read_bytes(); self.sql(statement)
                with self.assertRaisesRegex(ValueError, 'differ: ' + field): self.hooks()
                self.db.write_bytes(before)

    def test_legacy_lua_not_approved(self):
        self.hook_fixture()
        with self.assertRaisesRegex(ValueError, 'requires schema 1000'): self.hooks(42)

    def test_hook_unknown_phase_and_nul_rejected(self):
        self.hook_fixture(); m = self.inventory['packages'][0]['manifest']
        m['scripts'] = {'unknown': 'echo test'}
        with self.assertRaisesRegex(ValueError, 'unsupported hook phases'): self.hooks()
        m['scripts'] = {'install': 'echo%00bad'}
        with self.assertRaisesRegex(ValueError, 'NUL'): self.hooks()


    def collection_fixture(self):
        # Independent schema fixture matching the real pkg tables, not tables
        # generated from the verifier's SQL mapping.
        self.sql("""
CREATE TABLE categories(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE pkg_categories(package_id INTEGER,category_id INTEGER);
CREATE TABLE licenses(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE pkg_licenses(package_id INTEGER,license_id INTEGER);
CREATE TABLE users(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE pkg_users(package_id INTEGER,user_id INTEGER);
CREATE TABLE groups(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE pkg_groups(package_id INTEGER,group_id INTEGER);
CREATE TABLE provides(id INTEGER PRIMARY KEY,provide TEXT);
CREATE TABLE pkg_provides(package_id INTEGER,provide_id INTEGER);
CREATE TABLE requires(id INTEGER PRIMARY KEY,require TEXT);
CREATE TABLE pkg_requires(package_id INTEGER,require_id INTEGER);
CREATE TABLE shlibs(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE pkg_shlibs_required(package_id INTEGER,shlib_id INTEGER);
CREATE TABLE pkg_shlibs_provided(package_id INTEGER,shlib_id INTEGER);
CREATE TABLE pkg_shlibs_required_ignore(package_id INTEGER,shlib_id INTEGER);
CREATE TABLE pkg_shlibs_provided_ignore(package_id INTEGER,shlib_id INTEGER);
CREATE TABLE option(option_id INTEGER PRIMARY KEY,option TEXT);
CREATE TABLE pkg_option(package_id INTEGER,option_id INTEGER,value TEXT);
CREATE TABLE annotation(annotation_id INTEGER PRIMARY KEY,annotation TEXT);
CREATE TABLE pkg_annotation(package_id INTEGER,tag_id INTEGER,value_id INTEGER);
INSERT INTO categories VALUES(1,'base'); INSERT INTO pkg_categories VALUES(1,1);
INSERT INTO licenses VALUES(1,'BSD2CLAUSE'),(2,'literal, comma');
INSERT INTO pkg_licenses VALUES(1,1),(1,2);
INSERT INTO users VALUES(1,'service'); INSERT INTO pkg_users VALUES(1,1);
INSERT INTO groups VALUES(1,'service'); INSERT INTO pkg_groups VALUES(1,1);
INSERT INTO provides VALUES(1,'feature'); INSERT INTO pkg_provides VALUES(1,1);
INSERT INTO requires VALUES(1,'dependency'); INSERT INTO pkg_requires VALUES(1,1);
INSERT INTO shlibs VALUES(1,'required.so'),(2,'provided.so'),(3,'ignored-required.so'),(4,'ignored-provided.so');
INSERT INTO pkg_shlibs_required VALUES(1,1); INSERT INTO pkg_shlibs_provided VALUES(1,2);
INSERT INTO pkg_shlibs_required_ignore VALUES(1,3); INSERT INTO pkg_shlibs_provided_ignore VALUES(1,4);
INSERT INTO option VALUES(1,'FEATURE'),(2,'DISABLED');
INSERT INTO pkg_option VALUES(1,1,'on'),(1,2,'off');
INSERT INTO annotation VALUES(1,'scope'),(2,'value'),(3,'other');
INSERT INTO pkg_annotation VALUES(1,1,2),(1,3,1);
""")
        self.inventory['packages'][0]['manifest'].update({
            'categories': ['base'], 'licenses': ['BSD2CLAUSE', 'literal, comma'],
            'users': ['service'], 'groups': ['service'], 'provides': ['feature'],
            'requires': ['dependency'], 'shlibs_required': ['required.so'],
            'shlibs_provided': ['provided.so'], 'shlibs_required_ignore': ['ignored-required.so'],
            'shlibs_provided_ignore': ['ignored-provided.so'],
            'options': {'FEATURE': True, 'DISABLED': False},
            'annotations': {'scope': 'value', 'other': 'scope'}})

    def collections(self):
        return payload.check_collections(lambda s: payload.preflight.query_database(self.db, SQLITE, s), self.inventory)

    def test_all_collection_and_map_values(self):
        self.collection_fixture(); before = self.db.read_bytes()
        counts = self.collections()
        self.assertEqual(len(counts), 12)
        self.assertEqual(counts['licenses'], 2)
        self.assertEqual(counts['annotations'], 2)
        self.assertEqual(self.db.read_bytes(), before)

    def test_each_collection_value_mutation(self):
        self.collection_fixture()
        for table, column, row, field in [
            ('categories','name',1,'categories'), ('licenses','name',2,'licenses'),
            ('users','name',1,'users'), ('groups','name',1,'groups'),
            ('provides','provide',1,'provides'), ('requires','require',1,'requires'),
            ('shlibs','name',1,'shlibs_required'), ('shlibs','name',2,'shlibs_provided'),
            ('shlibs','name',3,'shlibs_required_ignore'), ('shlibs','name',4,'shlibs_provided_ignore')]:
            with self.subTest(field=field):
                before = self.db.read_bytes()
                self.sql('UPDATE '+table+' SET '+column+"='wrong' WHERE id="+str(row))
                with self.assertRaisesRegex(ValueError, 'differ: '+field): self.collections()
                self.db.write_bytes(before)

    def test_collection_associations_and_multiplicity(self):
        self.collection_fixture()
        for statement in ['UPDATE pkg_users SET package_id=2', 'DELETE FROM pkg_users',
                          'INSERT INTO pkg_users VALUES(1,1)']:
            with self.subTest(statement=statement):
                before = self.db.read_bytes(); self.sql(statement)
                with self.assertRaisesRegex(ValueError, 'differ: users'): self.collections()
                self.db.write_bytes(before)

    def test_map_values_keys_and_role_pairing(self):
        self.collection_fixture()
        for statement, field in [
            ("UPDATE pkg_option SET value='off' WHERE option_id=1", 'options'),
            ("UPDATE option SET option='OTHER' WHERE option_id=1", 'options'),
            ('UPDATE pkg_option SET package_id=2', 'options'),
            ('UPDATE pkg_annotation SET value_id=tag_id,tag_id=value_id', 'annotations'),
            ('DELETE FROM pkg_annotation WHERE tag_id=3', 'annotations'),
            ('UPDATE pkg_annotation SET package_id=2', 'annotations')]:
            with self.subTest(statement=statement):
                before = self.db.read_bytes(); self.sql(statement)
                with self.assertRaisesRegex(ValueError, 'differ: '+field): self.collections()
                self.db.write_bytes(before)

    def test_invalid_collection_inputs(self):
        self.collection_fixture(); m = self.inventory['packages'][0]['manifest']
        m['users'] = ['service', 'service']
        with self.assertRaisesRegex(ValueError, 'invalid manifest collection'): self.collections()
        m['users'] = ['service']; m['annotations'] = {'scope': False}
        with self.assertRaisesRegex(ValueError, 'invalid manifest map entry'): self.collections()
        m['annotations'] = {}; m['options'] = {'FEATURE': 1}
        with self.assertRaisesRegex(ValueError, 'invalid manifest map entry'): self.collections()


    def package_metadata_fixture(self):
        self.sql("""ALTER TABLE packages ADD COLUMN comment TEXT;
ALTER TABLE packages ADD COLUMN desc TEXT;
ALTER TABLE packages ADD COLUMN maintainer TEXT;
ALTER TABLE packages ADD COLUMN www TEXT;
ALTER TABLE packages ADD COLUMN prefix TEXT;
ALTER TABLE packages ADD COLUMN flatsize INTEGER;
ALTER TABLE packages ADD COLUMN licenselogic INTEGER;
ALTER TABLE packages ADD COLUMN dep_formula TEXT;
UPDATE packages SET comment='fixture',desc='description 100%',maintainer='test@example.invalid',
 www='https://example.invalid',prefix='/',flatsize=12,licenselogic=1,dep_formula=NULL;
""")
        for p in self.inventory['packages']:
            p['manifest'].update(comment='fixture', desc='description 100%25', maintainer='test@example.invalid',
                www='https://example.invalid', prefix='/', flatsize=12, licenselogic='single')

    def package_metadata(self):
        return payload.check_package_metadata(lambda s: payload.preflight.query_database(self.db, SQLITE, s), self.inventory)

    def test_package_metadata_and_license_logic(self):
        self.package_metadata_fixture()
        self.assertEqual(self.package_metadata(), {'package_metadata': 2})
        for logic, number in [('and',38), ('or',124)]:
            self.sql('UPDATE packages SET licenselogic='+str(number))
            for p in self.inventory['packages']: p['manifest']['licenselogic'] = logic
            self.package_metadata()

    def test_each_package_metadata_field(self):
        self.package_metadata_fixture()
        for field,value in [('comment',"'other'"),('desc',"'other'"),('maintainer',"'other'"),
                ('www','NULL'),('prefix',"'/other'"),('flatsize','13'),('licenselogic','124'),('dep_formula',"''")]:
            with self.subTest(field=field):
                before = self.db.read_bytes(); self.sql('UPDATE packages SET '+field+'='+value+' WHERE id=1')
                with self.assertRaisesRegex(ValueError,'differ: package metadata'): self.package_metadata()
                self.db.write_bytes(before)

    def test_invalid_package_metadata_inputs(self):
        self.package_metadata_fixture(); m = self.inventory['packages'][0]['manifest']
        m['flatsize'] = True
        with self.assertRaisesRegex(ValueError,'flat size'): self.package_metadata()
        m['flatsize'] = 12; m['desc'] = 'bad%00description'
        with self.assertRaisesRegex(ValueError,'NUL'): self.package_metadata()


    def test_omitted_license_logic_is_not_explicit_single(self):
        self.package_metadata_fixture()
        for p in self.inventory['packages']: p['manifest'].pop('licenselogic')
        self.sql('UPDATE packages SET licenselogic=0')
        self.package_metadata()
        self.inventory['packages'][0]['manifest']['licenselogic'] = 'single'
        with self.assertRaisesRegex(ValueError, 'differ: package metadata'): self.package_metadata()


    def config_fixture(self):
        self.sql('CREATE TABLE config_files(path TEXT,content TEXT,package_id INTEGER);')
        bodies = {'/file space': b'original\n', '/empty': b'',
                  '/bytes': b'\xff\x00after-nul\n'}
        p = self.inventory['packages'][0]
        p['manifest']['config'] = ['/file%20space', '/empty', '/bytes']
        p['config'] = list(bodies)
        p['entries'] = {path: dict(type='file', size=len(body),
            sha256=hashlib.sha256(body).hexdigest()) for path, body in bodies.items()}
        for path, body in bodies.items():
            self.sql("INSERT INTO config_files VALUES('" + path + "',CAST(X'" +
                     body.hex() + "' AS TEXT),1)")

    def configs(self):
        return payload.check_config_baselines(
            lambda s: payload.preflight.query_database(self.db, SQLITE, s), self.inventory)

    def test_config_bytes_and_empty_baseline(self):
        self.config_fixture()
        before = self.db.read_bytes()
        self.assertEqual(self.configs(), {'config_baselines': 3})
        self.assertEqual(before, self.db.read_bytes())

    def test_config_null_and_blob_are_not_empty_text(self):
        self.config_fixture()
        for value in ('NULL', "X''"):
            self.sql("UPDATE config_files SET content=" + value + " WHERE path='/empty'")
            with self.assertRaisesRegex(ValueError, 'missing or not text'): self.configs()

    def test_config_changed_content_owner_path_and_missing_row(self):
        self.config_fixture()
        for statement in ("UPDATE config_files SET content='site edited' WHERE path='/file space'",
                "UPDATE config_files SET package_id=2 WHERE path='/empty'",
                "UPDATE config_files SET path='/other' WHERE path='/empty'",
                "DELETE FROM config_files WHERE path='/empty'",
                "INSERT INTO config_files SELECT * FROM config_files LIMIT 1"):
            original = self.db.read_bytes()
            self.sql(statement)
            with self.assertRaisesRegex(ValueError, 'differ: configuration baselines'): self.configs()
            self.db.write_bytes(original)

    def test_config_archive_inputs_must_be_consistent(self):
        self.config_fixture()
        original = copy.deepcopy(self.inventory)
        p = self.inventory['packages'][0]
        p['config'] = []
        with self.assertRaisesRegex(ValueError, 'inconsistent'): self.configs()
        self.inventory = copy.deepcopy(original)
        self.inventory['packages'][0]['entries']['/empty']['type'] = 'symlink'
        with self.assertRaisesRegex(ValueError, 'regular archive payload'): self.configs()
        self.inventory = copy.deepcopy(original)
        self.inventory['packages'][0]['entries']['/empty']['size'] = True
        with self.assertRaisesRegex(ValueError, 'digest or size'): self.configs()


    def message_fixture(self):
        self.sql('ALTER TABLE packages ADD COLUMN message TEXT; '
                 'CREATE TABLE pkg_conflicts(package_id INTEGER,conflict_id INTEGER); '
                 'INSERT INTO pkg_conflicts VALUES(1,2);')
        messages = [{'message': 'literal %20 and newline\ninside'},
                    {'message': 'upgrade', 'type': 'upgrade', 'minimum_version': '1', 'maximum_version': '3'},
                    {'message': 'literal %20 and newline\ninside'}]
        self.inventory['packages'][0]['manifest'].update(messages=messages, conflicts=['shared'])
        self.sql("UPDATE packages SET message='" + json.dumps(messages) + "' WHERE id=1")

    def messages(self):
        return payload.check_messages_and_conflicts(
            lambda s: payload.preflight.query_database(self.db, SQLITE, s), self.inventory)

    def test_messages_order_duplicates_bounds_and_conflicts(self):
        self.message_fixture()
        before = self.db.read_bytes()
        self.assertEqual(self.messages(), {'message_packages': 1, 'conflicts': 1})
        self.assertEqual(before, self.db.read_bytes())

    def test_message_mutations_reject(self):
        self.message_fixture()
        original = self.db.read_bytes()
        messages = self.inventory['packages'][0]['manifest']['messages']
        variants = [None, [], messages[:-1], [messages[1], messages[0], messages[2]],
                    [dict(messages[0], message='decoded space'), *messages[1:]],
                    [messages[0], dict(messages[1], minimum_version='2'), messages[2]]]
        for value in variants:
            self.db.write_bytes(original)
            sql = 'NULL' if value is None else "'" + json.dumps(value) + "'"
            self.sql('UPDATE packages SET message=' + sql + ' WHERE id=1')
            with self.assertRaisesRegex(ValueError, 'differ: messages'): self.messages()

    def test_conflict_owner_target_missing_extra(self):
        self.message_fixture(); original = self.db.read_bytes()
        for sql in ('UPDATE pkg_conflicts SET package_id=2',
                    'UPDATE pkg_conflicts SET conflict_id=1',
                    'DELETE FROM pkg_conflicts',
                    'INSERT INTO pkg_conflicts VALUES(2,1)'):
            self.db.write_bytes(original); self.sql(sql)
            with self.assertRaisesRegex(ValueError, 'differ: conflicts'): self.messages()

    def test_message_inputs_reject_ambiguous_and_ignored_fields(self):
        self.message_fixture(); manifest = self.inventory['packages'][0]['manifest']
        manifest['message'] = 'duplicate spelling'
        with self.assertRaisesRegex(ValueError, 'ambiguous'): self.messages()
        del manifest['message']
        for value in [[{'message': 'x', 'type': 'unknown'}],
                      [{'message': 'x', 'minimum_version': '1'}],
                      [{'message': 'x', 'extra': 'ignored'}],
                      [{'message': 'x\x00y'}]]:
            manifest['messages'] = value
            with self.assertRaises(ValueError): self.messages()


    def internal_fixture(self):
        self.sql('ALTER TABLE packages ADD COLUMN mtree_id INTEGER; '
                 'ALTER TABLE packages ADD COLUMN pkg_format_version INTEGER; '
                 'ALTER TABLE packages ADD COLUMN manifestdigest TEXT; '
                 "DELETE FROM packages WHERE id=2; UPDATE packages SET name='lua-order-seed' WHERE id=1;")
        self.inventory = {'packages': [{'manifest': dict(name='lua-order-seed',
            origin='tests/lua-order-seed', version='1', arch='freebsd:16:x86:64')} ]}
        # Independently observed from the selected engine's real archive solver.
        self.native_digest = '2$2$j4gtco9xdmqhr4gh6q7a1gsnprp37s6dz7q9r783gy1f8dkab976caph98hpd39eftbn6j3f69ptd16bydmggapgen3ftmzsxi6pj8y'

    def internal(self):
        return payload.check_internal_package_fields(
            lambda s: payload.preflight.query_database(self.db, SQLITE, s), self.inventory)

    def test_solver_digest_independent_native_vector_and_null(self):
        self.internal_fixture()
        self.assertEqual(self.internal()['absent_solver_digests'], 1)
        self.sql("UPDATE packages SET manifestdigest='" + self.native_digest + "'")
        self.assertEqual(self.internal()['solver_digests'], 1)

    def test_solver_digest_corruption_and_unreviewed_formats(self):
        self.internal_fixture()
        for value in ('', '2$2$wrong', '2$0$unreviewed', '3$2$unreviewed'):
            self.sql("UPDATE packages SET manifestdigest='" + value + "'")
            with self.assertRaisesRegex(ValueError, 'differ: solver digest'): self.internal()

    def test_reserved_package_fields_reject(self):
        self.internal_fixture()
        for field in ('mtree_id', 'pkg_format_version'):
            self.sql('UPDATE packages SET ' + field + '=0')
            with self.assertRaisesRegex(ValueError, 'reserved package field'): self.internal()
            self.sql('UPDATE packages SET ' + field + '=NULL')

    def test_solver_identity_change_rejects(self):
        self.internal_fixture()
        self.sql("UPDATE packages SET manifestdigest='" + self.native_digest + "'")
        manifest = self.inventory['packages'][0]['manifest']
        for key in ('origin', 'version', 'arch'):
            original = manifest[key]; manifest[key] = original + '-changed'
            with self.assertRaisesRegex(ValueError, 'differ: solver digest'): self.internal()
            manifest[key] = original



if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--sqlite', type=Path, required=True)
    args, rest = parser.parse_known_args(); SQLITE = args.sqlite.resolve(strict=True)
    unittest.main(argv=[__file__, *rest])
