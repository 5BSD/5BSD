#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Protect pkg configuration registration independently of payload byte checks."""
import unittest
import archive_verify


class PackageConfiguration(unittest.TestCase):
    def check(self, manifest):
        return archive_verify.configuration_entries(
            manifest, {'etc/example.conf', 'usr/bin/example'},
            {'/etc/example.conf': {'tags': 'package=example,config'},
             '/usr/bin/example': {'tags': 'package=example'}},
            lambda name: name.lstrip('/').rstrip('/'))

    def test_configuration_registered(self):
        self.assertEqual(self.check({'config': ['/etc/example.conf']}),
                         ['etc/example.conf'])

    def test_missing_registration(self):
        with self.assertRaisesRegex(ValueError, 'differs'):
            self.check({})

    def test_extra_registration(self):
        with self.assertRaisesRegex(ValueError, 'differs'):
            self.check({'config': ['/etc/example.conf', '/usr/bin/example']})

    def test_outside_package(self):
        with self.assertRaisesRegex(ValueError, 'differs'):
            self.check({'config': ['/etc/example.conf', '/etc/another.conf']})

    def test_duplicate_normalized_path(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.check({'config': ['/etc/example.conf', 'etc/example.conf']})

    def test_invalid_inventory(self):
        for value in ('/etc/example.conf', {}, None, [None]):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'list of paths'):
                self.check({'config': value})

    def test_no_configuration_payload(self):
        self.assertEqual(archive_verify.configuration_entries(
            {}, {'usr/bin/example'}, {'/usr/bin/example': {'tags': 'package=example'}},
            lambda name: name.lstrip('/')), [])


if __name__ == '__main__':
    unittest.main()
