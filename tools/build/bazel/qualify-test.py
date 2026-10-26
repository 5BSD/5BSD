#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Input-boundary tests; real compiler/Make behavior is covered by qualify.py."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('qualify', Path(__file__).with_name('qualify.py'))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)

class Inputs(unittest.TestCase):
    def test_path_boundaries(self):
        for value in ('relative', '/tmp/a\nb', '/tmp/a$b'):
            with self.assertRaises(ValueError):
                q.safe_path(Path(value), exists=False)
        for value in ('/tmp/out', '/usr/obj', '/usr/obj/../../tmp/out'):
            with self.assertRaises(ValueError):
                q.safe_path(Path(value), exists=False, object_path=True)

    def test_symlink_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / 'link'
            link.symlink_to('/tmp')
            with self.assertRaises(ValueError):
                q.safe_path(link / 'output', exists=False, object_path=True)

    def test_make_identity(self):
        objtop = Path('/usr/obj/usr/src/amd64.amd64')
        valid = f'Entering world for amd64:amd64\n{objtop}\namd64\namd64\n'
        q.parse_identity(valid, objtop)
        for text in (valid.replace(str(objtop), '/usr/obj/other'),
                     valid.replace('amd64', 'aarch64'), valid + 'noise\n'):
            with self.assertRaises(ValueError):
                q.parse_identity(text, objtop)

    def test_resource_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            resource = root / 'usr/lib/clang/21'
            (resource / 'include').mkdir(parents=True)
            (resource / 'include/builtin.h').write_text('/* fixture */\n')
            self.assertEqual(q.toolchain_identity('x86_64-unknown-freebsd16.0\n', str(resource), root),
                             ('x86_64-unknown-freebsd16.0', '21'))
            for target in ('aarch64-unknown-freebsd16.0', 'x86_64-linux-gnu', 'x86_64-unknown-freebsd16.0\nnoise'):
                with self.assertRaises(ValueError):
                    q.toolchain_identity(target, str(resource), root)
            with self.assertRaises(ValueError):
                q.toolchain_identity('x86_64-unknown-freebsd16.0', str(root), root)
            (resource / 'include/builtin.h').unlink()
            with self.assertRaises(ValueError):
                q.toolchain_identity('x86_64-unknown-freebsd16.0', str(resource), root)

if __name__ == '__main__':
    unittest.main()
