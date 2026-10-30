#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Namespace and payload checks for declared source fixture materialization."""
from pathlib import Path
import tempfile
import unittest
from fixture_tree import materialize


class FixtureTreeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'input'
        self.source.write_bytes(b'fixture\x00bytes\n')
        self.output = self.root / 'output'

    def records(self, names):
        return [dict(source=str(self.source), destination=name) for name in names]

    def test_siblings_and_similar_prefixes(self):
        names = ['a/b', 'a/c', 'ab', 'abc/d/e']
        materialize(self.records(names), self.output)
        self.assertEqual(sorted(str(p.relative_to(self.output))
                                for p in self.output.rglob('*') if p.is_file()), sorted(names))
        for name in names:
            self.assertEqual((self.output / name).read_bytes(), self.source.read_bytes())
            self.assertEqual((self.output / name).stat().st_mode & 0o777, 0o444)

    def test_conflicts_rejected_before_output(self):
        for names in (['a', 'a/b'], ['a/b', 'a'], ['a/b/c', 'a/b'], ['a/b', 'a/b/c'], ['a', 'a']):
            with self.subTest(names=names), self.assertRaises(ValueError):
                materialize(self.records(names), self.output)
            self.assertFalse(self.output.exists())

    def test_invalid_destinations_rejected_before_output(self):
        for name in ('', '/absolute', 'a//b', '../escape', 'a/./b', 'a/../b', 'a\\b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                materialize(self.records([name]), self.output)
            self.assertFalse(self.output.exists())

    def test_existing_file_is_not_overwritten(self):
        self.output.mkdir()
        (self.output / 'kept').write_bytes(b'original')
        with self.assertRaises(FileExistsError):
            materialize(self.records(['kept']), self.output)
        self.assertEqual((self.output / 'kept').read_bytes(), b'original')


if __name__ == '__main__':
    unittest.main()
