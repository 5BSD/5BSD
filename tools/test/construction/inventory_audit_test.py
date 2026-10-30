# SPDX-License-Identifier: BSD-2-Clause
import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import json
from unittest.mock import patch
import unittest
import inventory_audit as audit


class InventoryAudit(unittest.TestCase):
    def setUp(self):
        self.helpers = audit.backend()
        directory = {'type': 'directory', 'mode': 0o755, 'uid': 0, 'gid': 0}
        self.inventory = {'format': 1, 'scope': 'package-payload-inventory',
            'packages': [{'name': 'example', 'version': '1', 'archive_sha256': 'a'*64,
                'directories': {}, 'config': ['/settings'], 'entries': {
                    '/shared': directory, '/settings': {'type': 'file', 'mode': 0o644},
                    '/tool': {'type': 'file', 'mode': 0o555},
                    '/alias': {'type': 'hardlink', 'target': '/tool'},
                    '/external': {'type': 'symlink', 'target': '/outside'}}}],
            'construction': {'actions': [{'name': 'database', 'package': 'example',
                'outputs': {'/database': {'type': 'file', 'mode': 0o600}}}]}}

    def test_cli_provenance_and_output_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'inventory.json'
            output = Path(directory) / 'review.json'
            raw = json.dumps(self.inventory, indent=1).encode() + b'\n'
            source.write_bytes(raw)
            argv = [sys.executable, '-B', audit.__file__, '--inventory',
                    str(source), '--output', str(output)]
            result = subprocess.run(argv, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_bytes())
            self.assertEqual(report['inventory_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertFalse(report['authentication_verified'])
            saved = output.read_bytes()
            # The CLI must not overwrite an earlier report, even with valid input.
            result = subprocess.run(argv, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_bytes(), saved)
            output.unlink()
            # Duplicate JSON keys must not silently change the reviewed inventory.
            source.write_text('{"format": 1, "format": 2}')
            result = subprocess.run(argv, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())

    def test_scope_and_links(self):
        r = audit.report(self.inventory, self.helpers)
        self.assertEqual(r['counts']['executable_candidates'], 2)
        self.assertEqual(r['objects']['/alias']['payload_path'], '/tool')
        self.assertFalse(r['objects']['/external']['executable_candidate'])
        self.assertTrue(r['objects']['/external']['link_review_required'])
        self.assertTrue(r['objects']['/settings']['configuration'])
        for key in ('authentication_verified', 'filesystem_reconciled', 'runtime_paths_complete',
                    'functional_coverage_verified', 'policy_assigned'):
            self.assertFalse(r[key])
        self.assertFalse(r['declared_generator_outputs']['/database']['execution_verified'])

    def test_shared_directory_owners(self):
        p = copy.deepcopy(self.inventory['packages'][0])
        p.update(name='second', config=[], entries={'/shared': p['entries']['/shared']})
        self.inventory['packages'].append(p)
        self.assertEqual(audit.report(self.inventory, self.helpers)['objects']['/shared']['owners'], ['example','second'])

    def test_conflicting_regular_ownership(self):
        p = copy.deepcopy(self.inventory['packages'][0]); p['name'] = 'second'
        self.inventory['packages'].append(p)
        with self.assertRaises(ValueError): audit.report(self.inventory, self.helpers)

    def test_cyclic_and_missing_hardlinks(self):
        for target in ('/alias', '/absent'):
            self.inventory['packages'][0]['entries']['/alias']['target'] = target
            with self.assertRaises(ValueError): audit.report(self.inventory, self.helpers)

    def test_noncanonical_path(self):
        self.inventory['packages'][0]['entries']['/a/../b'] = {'type':'file','mode':0o444}
        with self.assertRaises(ValueError): audit.report(self.inventory, self.helpers)

    def test_config_without_payload(self):
        self.inventory['packages'][0]['config'] = ['/absent']
        with self.assertRaises(ValueError): audit.report(self.inventory, self.helpers)

    def test_duplicate_generator(self):
        self.inventory['construction']['actions'] *= 2
        with self.assertRaises(ValueError): audit.report(self.inventory, self.helpers)

    def test_input_unchanged_and_order_independent(self):
        original = copy.deepcopy(self.inventory)
        first = audit.report(self.inventory, self.helpers)
        self.assertEqual(self.inventory, original)
        p = self.inventory['packages'][0]
        p['entries'] = dict(reversed(list(p['entries'].items())))
        self.assertEqual(first, audit.report(self.inventory, self.helpers))

    def test_state_overlaps_package_and_generator_inventory(self):
        package = self.inventory['packages'][0]
        package['entries']['/tool']['sha256'] = 'b' * 64
        package['entries'].update({
            '/state': {'type': 'directory'},
            '/state/tool': {'type': 'file', 'mode': 0o555},
            '/stateful/unrelated': {'type': 'file', 'mode': 0o444}})
        paths = ['/state', '/external/data', '/settings/child', '/settings', '/new']
        package['manifest'] = {'annotations': {self.helpers.STATE_ANNOTATION: json.dumps({
            'format': 1, 'requirements': [dict(name='state'+str(n), program='/tool',
                path=path, type='directory', lifetime='persistent', purpose='Review overlap')
                for n, path in enumerate(paths)]})}}
        self.inventory['construction']['actions'][0]['outputs'].update({
            '/state/generated': {'type': 'file'}, '/new': {'type': 'directory'},
            '/external': {'type': 'file'}})
        original = copy.deepcopy(self.inventory)
        report = audit.report(self.inventory, self.helpers)
        rows = report['state_inventory_review']
        self.assertEqual(rows['/state']['exact_package_object'], '/state')
        self.assertEqual(rows['/state']['contained_package_objects'], ['/state/tool'])
        self.assertEqual(rows['/external/data']['non_directory_package_ancestors'], ['/external'])
        self.assertEqual(rows['/settings/child']['non_directory_package_ancestors'], ['/settings'])
        self.assertEqual(rows['/settings']['exact_package_object'], '/settings')
        self.assertEqual(rows['/new']['exact_package_object'], None)
        self.assertEqual(rows['/state']['generator_overlaps'], {'/state/generated': 'descendant'})
        self.assertEqual(rows['/new']['generator_overlaps'], {'/new': 'exact'})
        self.assertEqual(rows['/external/data']['generator_overlaps'], {'/external': 'ancestor'})
        self.assertFalse(report['policy_assigned'])
        for row in rows.values():
            self.assertFalse(row['filesystem_resolution_verified'])
            self.assertEqual(row['policy_review'], 'required')
        self.assertEqual(original, self.inventory)
        package['entries'] = dict(reversed(list(package['entries'].items())))
        self.assertEqual(report, audit.report(self.inventory, self.helpers))

    def test_directory_mapping_candidates_are_reviewed_without_selection(self):
        package = self.inventory['packages'][0]
        package['entries']['/tool']['sha256'] = 'b' * 64
        package['entries']['/mapped/config'] = {'type': 'file', 'mode': 0o444}
        package['manifest'] = {'annotations': {self.helpers.STATE_ANNOTATION: json.dumps({
            'format': 2, 'requirements': [dict(name='workspace', program='/tool',
                path='/default', directory_mapping='/mapped', type='directory',
                lifetime='persistent', purpose='Alternative workspace')]})}}
        original = copy.deepcopy(self.inventory)
        report = audit.report(self.inventory, self.helpers)
        rows = report['state_inventory_review']
        self.assertIn('/default', rows)
        self.assertIn('/mapped', rows)
        self.assertEqual(rows['/mapped']['contained_package_objects'], ['/mapped/config'])
        self.assertFalse(rows['/mapped']['filesystem_resolution_verified'])
        self.assertFalse(report['policy_assigned'])
        self.assertEqual(original, self.inventory)

    def test_absent_state_declarations_do_not_infer_writable_paths(self):
        report = audit.report(self.inventory, self.helpers)
        self.assertEqual({}, report['state_inventory_review'])
        self.assertFalse(report['runtime_paths_complete'])
        self.assertFalse(report['policy_assigned'])


class StateRequirements(unittest.TestCase):
    def setUp(self):
        self.helpers = audit.backend()
        self.item = dict(name='queue', program='/usr/sbin/example',
            path='/var/spool/example', type='directory', lifetime='persistent',
            purpose='Queued work retained across restart')
        self.package = dict(name='example', version='1', archive_sha256='a'*64,
            entries={'/usr/sbin/example': dict(type='file', mode=0o555, sha256='b'*64)},
            directories={}, config=[], manifest={'annotations': {}})

    def declare(self, requirements=None):
        self.package['manifest']['annotations'][self.helpers.STATE_ANNOTATION] = json.dumps(
            dict(format=1, requirements=[self.item] if requirements is None else requirements))

    def test_owned_binding_and_no_authority(self):
        self.declare()
        r = self.helpers.state_requirements([self.package])
        self.assertFalse(r['authority_assigned'])
        self.assertFalse(r['runtime_paths_complete'])
        self.assertEqual(r['requirements'][0]['program_payload']['sha256'], 'b'*64)
        self.assertEqual(r['packages_without_declarations'], [])
        self.assertEqual(r['requirements'][0]['policy_review'], 'required')

    def test_missing_and_explicit_empty_are_distinct(self):
        self.assertEqual(self.helpers.state_requirements([self.package])['packages_without_declarations'], ['example'])
        self.declare([])
        r = self.helpers.state_requirements([self.package])
        self.assertEqual(r['requirements'], [])
        self.assertEqual(r['packages_without_declarations'], [])
        self.assertFalse(r['runtime_paths_complete'])

    def test_socket_requirement_is_boot_state_not_payload_or_authority(self):
        self.item.update(type='socket', lifetime='boot', path='/var/run/example.sock')
        self.declare()
        r = self.helpers.state_requirements([self.package])
        self.assertEqual('socket', r['requirements'][0]['type'])
        self.assertFalse(r['authority_assigned'])
        self.assertFalse(r['runtime_paths_complete'])
        for lifetime in ('persistent', 'cache'):
            self.item['lifetime'] = lifetime
            self.declare()
            with self.assertRaisesRegex(ValueError, 'socket state must have boot lifetime'):
                self.helpers.state_requirements([self.package])

    def test_malformed_declarations(self):
        for key, value in [('path', '/'), ('path', '/var/../etc/key'),
                           ('program', '/foreign/program'), ('type', 'symlink'),
                           ('lifetime', 'forever'), ('purpose', 'bad\x00text'),
                           ('name', '../bad')]:
            with self.subTest(key=key, value=value):
                saved = copy.deepcopy(self.item)
                self.item[key] = value
                self.declare()
                with self.assertRaises(ValueError): self.helpers.state_requirements([self.package])
                self.item = saved
        self.declare([self.item, self.item])
        with self.assertRaises(ValueError): self.helpers.state_requirements([self.package])

    def test_strict_json_and_version(self):
        for text in ('{"format":1,"format":1,"requirements":[]}',
                     '{"format":true,"requirements":[]}',
                     '{"format":1,"requirements":[],"grant":true}',
                     '{"format":1,"requirements":NaN}'):
            self.package['manifest']['annotations'][self.helpers.STATE_ANNOTATION] = text
            with self.assertRaises(ValueError): self.helpers.state_requirements([self.package])

    def test_consumer_payload_not_names_alone(self):
        self.declare()
        for payload in (dict(type='file', mode=0o444, sha256='b'*64),
                        dict(type='file', mode=0o555, sha256='bad'),
                        dict(type='symlink', target='/outside'),
                        dict(type='hardlink', target='/usr/sbin/example')):
            self.package['entries']['/usr/sbin/example'] = payload
            with self.assertRaises(ValueError): self.helpers.state_requirements([self.package])

    def test_shared_state_path_and_disagreement(self):
        self.declare()
        second = copy.deepcopy(self.package)
        second['name'] = 'other'
        result = self.helpers.state_requirements([second, self.package])
        row = result['path_review'][self.item['path']]
        self.assertEqual([c['package'] for c in row['consumers']], ['example', 'other'])
        self.assertEqual(row['conflicts'], [])
        self.assertEqual(row['policy_review'], 'required')
        changed = dict(self.item, type='file', lifetime='boot')
        second['manifest']['annotations'][self.helpers.STATE_ANNOTATION] = json.dumps(
            dict(format=1, requirements=[changed]))
        result = self.helpers.state_requirements([second, self.package])
        self.assertEqual(result['path_review'][self.item['path']]['conflicts'], ['types', 'lifetimes'])
        self.assertFalse(result['authority_assigned'])
        self.assertEqual(result, self.helpers.state_requirements([self.package, second]))

    def test_component_ancestry_and_file_conflict(self):
        items = [dict(self.item, name='parent', path='/var/state'),
            dict(self.item, name='file', path='/var/state/db', type='file'),
            dict(self.item, name='child', path='/var/state/db/item'),
            dict(self.item, name='neighbor', path='/var/stateful')]
        self.declare(items)
        rows = self.helpers.state_requirements([self.package])['path_review']
        self.assertEqual(rows['/var/state/db/item']['declared_ancestors'], ['/var/state', '/var/state/db'])
        self.assertEqual(rows['/var/state/db/item']['file_ancestors'], ['/var/state/db'])
        self.assertEqual(rows['/var/state/db/item']['conflicts'], ['file_ancestor'])
        self.assertEqual(rows['/var/stateful']['declared_ancestors'], [])
        self.assertEqual(rows['/var/state/db']['conflicts'], [])
        self.declare(list(reversed(items)))
        self.assertEqual(rows, self.helpers.state_requirements([self.package])['path_review'])

    def test_package_declaration_does_not_cover_other_programs_or_aliases(self):
        self.declare()
        self.package['entries'].update({
            '/other': dict(type='file', mode=0o555, sha256='c'*64),
            '/alias': dict(type='hardlink', target=self.item['program']),
            '/data': dict(type='file', mode=0o444, sha256='d'*64)})
        inventory = dict(format=1, scope='package-payload-inventory',
            packages=[self.package], construction={'actions': []})
        result = audit.report(inventory, self.helpers)
        review = result['packages']['example']['state_review']
        self.assertEqual(review['candidates_without_declarations'], ['/alias', '/other'])
        rows = review['executable_candidates']
        self.assertNotIn('/data', rows)
        self.assertEqual(rows[self.item['program']]['declared_requirements'], ['queue'])
        for row in rows.values():
            self.assertFalse(row['runtime_paths_complete'])
            self.assertFalse(row['functional_coverage_verified'])
        # Explicitly empty package metadata does not clear program review gaps.
        self.declare([])
        review = audit.report(inventory, self.helpers)['packages']['example']['state_review']
        self.assertEqual(review['candidates_without_declarations'],
            ['/alias', '/other', self.item['program']])

    def test_inventory_pipeline_carries_requirements(self):
        self.declare()
        with patch.object(self.helpers, 'inventory_archive', return_value=self.package):
            r = self.helpers.inventory_packages(['/input/example.pkg'])
        self.assertEqual(len(r['state_requirements']['requirements']), 1)
        # The review report derives from package data, not a supplied approval.
        r['state_requirements']['authority_assigned'] = True
        self.assertFalse(audit.report(r, self.helpers)['state_requirements']['authority_assigned'])


if __name__ == '__main__': unittest.main()
