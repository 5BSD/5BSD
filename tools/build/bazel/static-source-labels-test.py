#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Static source quoted includes must remain paths when snapshot labels change."""
import tempfile
import unittest
from pathlib import Path
from libmd_environment import digest
import static_sources

class StaticSourceLabels(unittest.TestCase):
    def test_absolute_and_relative_labels_preserve_include_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            src = Path(directory)
            (src / "obj").mkdir()
            origin = src / 'lib/example/original.c'
            origin.parent.mkdir(parents=True)
            origin.write_text('#include "private.h"\n')
            component = dict(metadata=dict(LIB='example', STATICOBJS='alias.o'),
                static_objects=[dict(object='alias.o', source='alias.c',
                    origin='lib/example/original.c', sha256=digest(origin),
                    variant='regular', compile_context=dict(source='alias.c',
                    target='alias.o', language='c', static_flags=[], flags=[]))])
            for label in ('sources/lib/example/original.c', '//:sources/lib/example/original.c'):
                with self.subTest(label=label):
                    rules = []
                    def rule(kind, **attrs):
                        rules.append((kind, attrs))
                    labels, headers = static_sources.emit(component, src, src/'obj',
                        lambda path: label, rule, {})
                    self.assertEqual(rules[0][1]['source'], label)
                    self.assertEqual(rules[0][1]['copts'], ['-iquote', 'sources/lib/example'])
                    self.assertIn(origin.parent, headers)
                    self.assertEqual(labels, [':example_static_source_0'])

if __name__ == '__main__':
    unittest.main()
