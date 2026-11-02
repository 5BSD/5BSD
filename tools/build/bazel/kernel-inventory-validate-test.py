#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import copy
import unittest
from kernel_inventory_validate import validate


class KernelInventoryValidationTests(unittest.TestCase):
    def setUp(self):
        self.expected = dict(format=1, kernel_identity='EXAMPLE', machine='amd64',
                             machine_arch='amd64', inputs=[
            dict(source='kern/one.c', origin='kernel', object='one.o', flags=0,
                 compile_with=None, depends=None),
            dict(source='generated.h', origin='generated', object=None, flags=2,
                 compile_with='renderer "quoted"', depends='input.txt')])

    def reject(self, actual):
        with self.assertRaises(ValueError):
            validate(actual, self.expected)

    def test_exact_catalog_passes(self):
        result = validate(copy.deepcopy(self.expected), self.expected)
        self.assertEqual((result['selected_inputs'], result['selected_objects']), (2, 1))

    def test_addition_removal_and_order_drift_fail(self):
        for rows in (self.expected['inputs'][:1],
                     self.expected['inputs'] + [self.expected['inputs'][0]],
                     list(reversed(self.expected['inputs']))):
            actual = copy.deepcopy(self.expected)
            actual['inputs'] = rows
            self.reject(actual)

    def test_same_basename_different_source_and_recipe_metadata_fail(self):
        for field, value in [('source', 'other/one.c'), ('origin', 'generated'),
                             ('object', 'prefix_one.o'), ('flags', 32),
                             ('compile_with', 'different compiler'), ('depends', 'new.input')]:
            actual = copy.deepcopy(self.expected)
            actual['inputs'][0][field] = value
            self.reject(actual)

    def test_no_object_metadata_is_validated(self):
        actual = copy.deepcopy(self.expected)
        actual['inputs'][1]['compile_with'] = 'changed header producer'
        self.reject(actual)

    def test_identity_schema_and_version_fail(self):
        for field, value in [('kernel_identity', 'OTHER'), ('machine', 'arm64'),
                             ('machine_arch', 'aarch64'), ('format', 2), ('format', True)]:
            actual = copy.deepcopy(self.expected)
            actual[field] = value
            self.reject(actual)
        actual = copy.deepcopy(self.expected)
        actual['unrecognized'] = True
        self.reject(actual)


if __name__ == '__main__':
    unittest.main()
