# SPDX-License-Identifier: BSD-2-Clause
"""Validate evidence selected for independent populated-state readback."""
import copy
import unittest
import state_readback as subject


class Evidence(unittest.TestCase):
    def setUp(self):
        self.receipt = dict(pool_guid='1', parent_guid='2', dataset_guid='3', dataset='pool/state/var',
            scope='offline-new-state-dataset', result='PASS', source_observation_sha256='a'*64,
            initialization=dict(scope='offline-empty-state-initialization', result='PASS',
                source_observation_sha256='a'*64, initialized_observation_sha256='a'*64))
        self.document = dict(format=1, scope='initialized-state-vm-transport',
            output_disk_sha256='b'*64, report=dict(result='PASS',
                scope='ordinary-state-initialization', pool_exported=True,
                bindings=[dict(path='/var', receipt=self.receipt)]))

    def test_populated_evidence(self):
        rows, initialized = subject.selection(self.document)
        self.assertTrue(initialized)
        self.assertEqual(rows[0]['receipt'], self.receipt)

    def test_empty_allocation_does_not_claim_contents(self):
        allocation = dict(result='PASS', scope='empty-state-dataset-allocation', pool_exported=True,
            bindings=[dict(receipt=dict(pool_guid='1', parent_guid='2', dataset_guid='3', dataset='pool/state/var'))])
        self.assertFalse(subject.selection(allocation)[1])

    def test_mismatched_seed(self):
        self.receipt['initialization']['initialized_observation_sha256'] = 'c'*64
        with self.assertRaisesRegex(ValueError, 'seed observations'): subject.selection(self.document)

    def test_missing_disk_binding(self):
        del self.document['output_disk_sha256']
        with self.assertRaisesRegex(ValueError, 'output disk hash'): subject.selection(self.document)

    def test_incomplete_initialization(self):
        self.receipt['initialization']['result'] = 'RUNNING'
        with self.assertRaisesRegex(ValueError, 'seed observations'): subject.selection(self.document)

    def test_unexported_pool(self):
        self.document['report']['pool_exported'] = False
        with self.assertRaisesRegex(ValueError, 'exported'): subject.selection(self.document)

    def test_invalid_guid(self):
        self.receipt['pool_guid'] = '-f'
        with self.assertRaisesRegex(ValueError, 'GUID'): subject.selection(self.document)


    def test_duplicate_dataset_guid(self):
        other = copy.deepcopy(self.document['report']['bindings'][0])
        other['path'] = '/etc'; other['receipt']['dataset'] = 'pool/state/etc'
        self.document['report']['bindings'].append(other)
        with self.assertRaisesRegex(ValueError, 'duplicate selected dataset'): subject.selection(self.document)

    def test_duplicate_dataset_name(self):
        other = copy.deepcopy(self.document['report']['bindings'][0])
        other['path'] = '/etc'; other['receipt']['dataset_guid'] = '4'
        self.document['report']['bindings'].append(other)
        with self.assertRaisesRegex(ValueError, 'duplicate selected dataset'): subject.selection(self.document)

    def test_duplicate_boundary(self):
        other = copy.deepcopy(self.document['report']['bindings'][0])
        other['receipt']['dataset_guid'] = '4'; other['receipt']['dataset'] = 'pool/state/etc'
        self.document['report']['bindings'].append(other)
        with self.assertRaisesRegex(ValueError, 'duplicate selected writable'): subject.selection(self.document)

    def test_invalid_boundary(self):
        for value in (None, '/', 'var', '/var/../etc', '/var/', '/var//db', '/var\n'):
            with self.subTest(value=value):
                self.document['report']['bindings'][0]['path'] = value
                with self.assertRaisesRegex(ValueError, 'canonical writable boundary'): subject.selection(self.document)

    def test_distinct_datasets_and_boundaries(self):
        other = copy.deepcopy(self.document['report']['bindings'][0])
        other['path'] = '/etc'; other['receipt']['dataset_guid'] = '4'
        other['receipt']['dataset'] = 'pool/state/etc'
        self.document['report']['bindings'].append(other)
        self.assertEqual(len(subject.selection(self.document)[0]), 2)


if __name__ == '__main__': unittest.main()
