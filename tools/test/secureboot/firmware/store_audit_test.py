# SPDX-License-Identifier: BSD-2-Clause
import copy
import struct
import unittest
from store_audit import DATABASE_GUID, X509, check_revocation, signatures


def record(cert):
    item = bytes(16) + cert
    return X509 + struct.pack('<III', 28 + len(item), 0, len(item)) + item


class StoreAuditTest(unittest.TestCase):
    def setUp(self):
        self.before = {'version': 2, 'variables': [
            {'guid': DATABASE_GUID, 'name': 'db', 'attr': 39,
             'data': (record(b'primary') + record(b'secondary')).hex()},
            {'guid': DATABASE_GUID, 'name': 'dbx', 'attr': 39, 'data': ''}]}
        self.after = copy.deepcopy(self.before)
        self.after['variables'][1]['data'] = record(b'primary').hex()

    def check(self):
        check_revocation(self.before, self.after, b'primary', b'secondary')

    def test_expected_append(self):
        self.check()

    def test_removed_allowed_signer(self):
        self.after['variables'][0]['data'] = record(b'secondary').hex()
        self.assertRaises(ValueError, self.check)

    def test_wrong_revocation(self):
        self.after['variables'][1]['data'] = record(b'secondary').hex()
        self.assertRaises(ValueError, self.check)

    def test_duplicate_variable(self):
        self.after['variables'].append(self.after['variables'][1])
        self.assertRaises(ValueError, self.check)

    def test_changed_attributes(self):
        self.after['variables'][1]['attr'] = 7
        self.assertRaises(ValueError, self.check)

    def test_duplicate_revocation(self):
        self.after['variables'][1]['data'] *= 2
        self.assertRaises(ValueError, self.check)

    def test_truncated_lists(self):
        data = record(b'certificate')
        for size in range(1, len(data)):
            with self.subTest(size=size):
                self.assertRaises(ValueError, signatures, data[:size])

    def test_invalid_sizes(self):
        for size, header, entry in ((0, 0, 20), (28, 0, 0), (28, 1, 17), (29, 0, 16), (29, 0, 20)):
            self.assertRaises(ValueError, signatures, X509 + struct.pack('<III', size, header, entry) + b'x')


if __name__ == '__main__':
    unittest.main()
