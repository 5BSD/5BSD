# SPDX-License-Identifier: BSD-2-Clause
"""Test fresh-state declarations against independently selected world records."""
import json
from pathlib import Path
import tempfile
import unittest
from construction_records import construction_records
from world_package_inventory import inventory


def file(path):
    return dict(destination=path, type='file', source='generated/' + path.rsplit('/', 1)[-1],
                owner='root', group='wheel', mode='0444', tags=[])


class Construction(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.metadata = Path(self.temporary.name) / 'tree.json'
        self.bundle = file('/etc/ssl/cert.pem')
        self.cert = file('/etc/ssl/certs/generated-name.0')
        self.directory = dict(destination='/etc/ssl/certs', type='dir',
                              owner='root', group='wheel', mode='0755', tags=[])
        self.tree = dict(prefix='/etc/ssl', metadata=str(self.metadata))
        self.write([self.directory, self.bundle, self.cert])

    def write(self, records):
        self.metadata.write_text(json.dumps(dict(records=records)))

    def test_selected_tree_and_static_state_reconcile_exactly(self):
        account = file('/etc/pwd.db')
        declarations = construction_records([account], [self.tree])
        records = [account, self.directory, self.bundle, self.cert]
        got = inventory(records, declarations, [])
        self.assertEqual(set(got['construction']), {'/etc/pwd.db', '/etc/ssl/cert.pem', '/etc/ssl/certs/generated-name.0'})
        self.assertEqual(got['packages'], {})
        self.assertEqual(set(got['shared_directories']), {'/etc/ssl/certs'})

    def test_unselected_or_different_generated_state_fails_reconciliation(self):
        declarations = construction_records([], [self.tree])
        for records in [[self.bundle], [dict(self.bundle, mode='0600'), self.cert]]:
            with self.subTest(records=records), self.assertRaises(ValueError):
                inventory(records, declarations, [])
        with self.assertRaises(ValueError):
            inventory([self.bundle, self.cert], [], [])

    def test_new_and_removed_outputs_follow_producer_metadata(self):
        extra = file('/etc/ssl/certs/another-subject.0')
        for records in [[self.bundle, self.cert, extra], [self.bundle]]:
            with self.subTest(records=records):
                self.write(records)
                declarations = construction_records([], [self.tree])
                self.assertEqual(set(inventory(records, declarations, [])['construction']),
                                 {record['destination'] for record in records})

    def test_duplicates_across_static_and_generated_inputs_are_refused(self):
        for records, trees in [([self.bundle], [self.tree]), ([], [self.tree, self.tree])]:
            with self.subTest(records=records), self.assertRaisesRegex(ValueError, 'distinct'):
                construction_records(records, trees)

    def test_package_claims_and_unmodeled_types_are_refused(self):
        for record in [dict(self.cert, tags=['package=caroot']),
                       dict(self.directory, tags=['package=caroot']),
                       dict(self.cert, type='symlink', link='/unrelated'),
                       dict(self.cert, source=''), dict(self.cert, destination='/etc/ssl')]:
            with self.subTest(record=record), self.assertRaises(ValueError):
                self.write([record])
                construction_records([], [self.tree])

    def test_escape_and_noncanonical_paths_are_refused(self):
        for path in ['/etc/ssl-other/cert.pem', '/etc/ssl/../passwd',
                     '/etc/ssl/./cert.pem', '//etc/ssl/cert.pem', '/etc/ssl/',
                     '/etc/ssl/a\\b', '/etc/ssl/a b']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.write([dict(self.cert, destination=path)])
                construction_records([], [self.tree])
        with self.assertRaisesRegex(ValueError, 'bounded'):
            construction_records([], [dict(self.tree, prefix='/')])

    def test_malformed_installation_metadata_is_refused(self):
        for value in [None, {}, 'records']:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'installation records'):
                self.metadata.write_text(json.dumps(dict(records=value)))
                construction_records([], [self.tree])


if __name__ == '__main__':
    unittest.main()
