# SPDX-License-Identifier: BSD-2-Clause
import tempfile
from pathlib import Path
import unittest
from install_tree import installation_request


class TreeInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.tree = Path(self.temporary.name) / 'tree'
        self.tree.mkdir()
        self.plan = dict(format=1, tree=str(self.tree), prefix='/usr/share/generated', files=[],
            extra_directories=[], owner='root', group='wheel', file_mode='0444',
            directory_mode='0755', file_tags=['package=generated'], directory_tags=[],
            archive=dict(records=[], epoch=0))

    def file(self, name):
        path = self.tree / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(name.encode())
        return str(path)

    def test_new_generated_names_and_ancestors_are_included(self):
        files = [self.file('Area/One'), self.file('New/Deep/Two')]
        records = installation_request(self.plan, files)['records']
        self.assertEqual({r['destination'] for r in records if r['type'] == 'file'},
                         {'/usr/share/generated/Area/One', '/usr/share/generated/New/Deep/Two'})
        self.assertEqual({r['destination'] for r in records if r['type'] == 'dir'},
                         {'/usr/share/generated', '/usr/share/generated/Area',
                          '/usr/share/generated/New', '/usr/share/generated/New/Deep'})

    def test_duplicate_expanded_file_is_rejected(self):
        file = self.file('One')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            installation_request(self.plan, [file, file])

    def test_additional_payload_cannot_replace_generated_file(self):
        file = self.file('One')
        self.plan['files'] = [dict(source=file, destination='One')]
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            installation_request(self.plan, [file])

    def test_expansion_cannot_escape_declared_tree(self):
        with self.assertRaisesRegex(ValueError, 'outside declared tree'):
            installation_request(self.plan, [str(self.tree.parent / 'outside')])

    def test_noncanonical_and_traversing_destinations_are_rejected(self):
        file = self.file('One')
        for destination in ['.', '..', 'A/../B', '/absolute', 'A//B', 'A\\B', 'A B']:
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                self.plan['files'] = [dict(source=file, destination=destination)]
                installation_request(self.plan, [])

    def test_files_cannot_be_used_as_directories(self):
        file = self.file('Area/One')
        self.plan['files'] = [dict(source=file, destination='Area')]
        with self.assertRaisesRegex(ValueError, 'directory'):
            installation_request(self.plan, [file])
        self.plan['files'] = []
        self.plan['extra_directories'] = ['Area/One/Child']
        with self.assertRaisesRegex(ValueError, 'directory'):
            installation_request(self.plan, [file])

    def test_explicit_empty_compatibility_directories_are_retained(self):
        self.plan['extra_directories'] = ['Empty/Child']
        records = installation_request(self.plan, [])['records']
        self.assertEqual({r['destination'] for r in records},
                         {'/usr/share/generated', '/usr/share/generated/Empty',
                          '/usr/share/generated/Empty/Child'})
        self.assertTrue(all(r['tags'] == [] for r in records))

    def test_root_prefix_and_invalid_modes_are_rejected(self):
        self.plan['prefix'] = '/'
        with self.assertRaises(ValueError):
            installation_request(self.plan, [])
        self.plan['prefix'] = '/usr/share/generated'
        self.plan['file_mode'] = '0788'
        with self.assertRaises(ValueError):
            installation_request(self.plan, [])


if __name__ == '__main__':
    unittest.main()
