#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
import unittest
from static_archive_check import duplicates


class SymbolTests(unittest.TestCase):
    def test_strong_and_ifunc(self):
        for kind in ('T', 'D', 'B', 'R', 'i'):
            text = f'a.a[x.o]: f {kind} 0 8\na.a[y.o]: f {kind} 0 8\n'
            self.assertEqual(duplicates(text), {'f': ['a.a[x.o]', 'a.a[y.o]']})

    def test_coalesced(self):
        for kind in ('W', 'V', 'C', 'u'):
            text = f'a.a[x.o]: f {kind} 0 8\na.a[y.o]: f {kind} 0 8\n'
            self.assertEqual(duplicates(text), {})

    def test_weak_and_strong(self):
        self.assertEqual(duplicates('a.a[x.o]: f W 0 8\na.a[y.o]: f T 0 8'), {})

    def test_malformed_fails(self):
        for text in ('garbage', 'a.a[x.o]: f ? 0 8'):
            with self.assertRaises(ValueError):
                duplicates(text)

    def test_archive_path_spaces(self):
        self.assertEqual(duplicates('/a path/a.a[x.o]: f T 0 8'), {})


if __name__ == '__main__':
    unittest.main()
