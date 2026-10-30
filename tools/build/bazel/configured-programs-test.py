#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Keep C/C++ program selection aligned with maintained Make recursion."""
import subprocess
import tempfile
import unittest
from pathlib import Path
import configured_programs


class ProgramSelections(unittest.TestCase):
    def test_effective_make_inventory_and_language(self):
        with tempfile.TemporaryDirectory(prefix='program-selection-') as directory:
            root = Path(directory)
            (root / 'Makefile').write_text('PROGS= plain\nPROGS_CXX= modern\n.include <bsd.progs.mk>\n')
            def query(keys, extra=()):
                result = subprocess.run(['/usr/bin/make', '-m', str(Path(__file__).resolve().parents[3] / 'share/mk'), *extra,
                    *[v for key in keys for v in ('-V', key)]], cwd=root,
                    check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                rows = result.stdout.splitlines()
                self.assertEqual(len(rows), len(keys))
                return dict(zip(keys, rows))
            metadata = query(['PROGS', 'PROGS_CXX', 'x.modern'])
            selected = configured_programs.selections(metadata)
            self.assertEqual(selected, [('plain', ['PROG=plain']),
                                        ('modern', ['PROG=modern', 'PROG_CXX=modern'])])
            for name, extra in selected:
                effective = query(['PROG', 'PROG_CXX', 'SRCS'], extra)
                self.assertEqual(effective['PROG'], name)
                self.assertEqual(effective['PROG_CXX'], name if name == 'modern' else '')
                self.assertEqual(effective['SRCS'], name + ('.cc' if name == 'modern' else '.c'))
            self.assertEqual(metadata['x.modern'], selected[1][1][1])

    def test_no_programs(self):
        self.assertEqual(configured_programs.selections(dict(PROGS='', PROGS_CXX='')), [])

    def test_duplicate_effective_inventory_rejected(self):
        for metadata in (dict(PROGS='same same', PROGS_CXX=''),
                         dict(PROGS='same', PROGS_CXX='same same')):
            with self.subTest(metadata=metadata), self.assertRaisesRegex(ValueError, 'duplicate'):
                configured_programs.selections(metadata)

    def test_unfolded_cpp_inventory_rejected(self):
        with self.assertRaisesRegex(ValueError, 'absent'):
            configured_programs.selections(dict(PROGS='plain', PROGS_CXX='modern'))


if __name__ == '__main__':
    unittest.main()
