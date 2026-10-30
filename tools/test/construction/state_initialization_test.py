# SPDX-License-Identifier: BSD-2-Clause
"""Reject incomplete or ambiguous allocation-to-generation mappings."""
import copy
import importlib.util
from pathlib import Path
import unittest
import state_initialization as subject

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('state_storage', here.parents[1] / 'build/capimage/state_storage.py')
state = importlib.util.module_from_spec(spec); spec.loader.exec_module(state)


class Selection(unittest.TestCase):
    def setUp(self):
        self.projections = [dict(boundary=None, content='immutable'),
                            dict(boundary='/var', content='ordinary', observed={})]
        self.receipt = dict(scope='offline-new-state-allocation', result='PASS',
            dataset='selected/state/var', pool_guid='1', parent_guid='2', dataset_guid='3',
            pool_synced=True, left_unmounted=True, dataset_identity_verified=True)
        self.allocation = dict(format=1, result='PASS', scope='empty-state-dataset-allocation',
            pool_exported=True, initialized=False, bindings=[dict(path='/var', receipt=self.receipt)])

    def test_complete_mapping(self):
        rows, parent = subject.select(self.projections, self.allocation, state)
        self.assertEqual(parent, ('selected/state', '1', '2'))
        self.assertEqual(rows[0][1], self.receipt)

    def test_missing_boundary(self):
        self.projections.append(dict(boundary='/etc', content='ordinary', observed={}))
        with self.assertRaisesRegex(ValueError, 'cover exactly'): subject.select(self.projections, self.allocation, state)

    def test_duplicate_boundary(self):
        self.allocation['bindings'] *= 2
        with self.assertRaisesRegex(ValueError, 'duplicate'): subject.select(self.projections, self.allocation, state)

    def test_reused_dataset(self):
        self.allocation['bindings'].append(dict(path='/etc', receipt=copy.deepcopy(self.receipt)))
        with self.assertRaisesRegex(ValueError, 'identity reused'): subject.select(self.projections, self.allocation, state)

    def test_protected_not_silently_ordinary(self):
        self.projections[1]['content'] = 'protected'
        with self.assertRaisesRegex(ValueError, 'protected state'): subject.select(self.projections, self.allocation, state)

    def test_unexported_allocation(self):
        self.allocation['pool_exported'] = False
        with self.assertRaisesRegex(ValueError, 'exported'): subject.select(self.projections, self.allocation, state)

    def test_guid_not_an_option(self):
        for value in ('-f', '0', str(2**64), 1, None):
            self.receipt['pool_guid'] = value
            with self.assertRaisesRegex(ValueError, 'GUID'): subject.select(self.projections, self.allocation, state)

    def test_incomplete_receipt(self):
        self.receipt['pool_synced'] = False
        with self.assertRaisesRegex(ValueError, 'completed'): subject.select(self.projections, self.allocation, state)


if __name__ == '__main__': unittest.main()
