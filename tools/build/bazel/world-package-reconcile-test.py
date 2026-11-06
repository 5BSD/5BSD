# SPDX-License-Identifier: BSD-2-Clause
import copy
import unittest
from world_package_reconcile import reconcile


class Coverage(unittest.TestCase):
    def setUp(self):
        self.inventory = dict(format=1, scope='world-package-inventory',
            packages={'runtime': [dict(type='file', destination='/bin/sh')]},
            construction={'/etc/pwd.db': {}}, summary=dict(nondirectory_paths=2))
        self.catalogue = dict(format=1, scope='world-package-family-set', prefix='Org', version='1',
            families={'runtime': {}, 'retired': {}},
            packages={'runtime': dict(metadata_only=False), 'retired': dict(metadata_only=True)})

    def test_explicit_transition_and_construction(self):
        result = reconcile(self.inventory, self.catalogue)
        self.assertEqual(result['metadata_only'], ['retired'])
        self.assertEqual(result['construction'], ['/etc/pwd.db'])
        self.assertEqual(result['summary']['payload_packages'], 1)

    def test_unselected_payload(self):
        self.inventory['packages']['unselected'] = [dict(type='file')]
        with self.assertRaisesRegex(ValueError, 'lacks selected package metadata: unselected'):
            reconcile(self.inventory, self.catalogue)

    def test_missing_payload(self):
        self.catalogue['packages']['missing'] = dict(metadata_only=False)
        with self.assertRaisesRegex(ValueError, 'has no payload: missing'):
            reconcile(self.inventory, self.catalogue)

    def test_directory_only_is_not_payload(self):
        self.inventory['packages']['runtime'] = [dict(type='dir')]
        with self.assertRaisesRegex(ValueError, 'has no payload: runtime'):
            reconcile(self.inventory, self.catalogue)

    def test_metadata_only_cannot_claim_files_or_directories(self):
        for kind in ['file', 'dir']:
            with self.subTest(kind=kind):
                data = copy.deepcopy(self.inventory)
                data['packages']['retired'] = [dict(type=kind)]
                with self.assertRaisesRegex(ValueError, 'metadata-only package has installation claims: retired'):
                    reconcile(data, self.catalogue)


if __name__ == '__main__':
    unittest.main()
