#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Ensure shared script lowering cannot admit undeclared linker inputs."""
from pathlib import Path
import tempfile
import unittest
from libmd_environment import digest
from shared_link_script import dynamic_group


class SharedGroupTests(unittest.TestCase):
    def check_group(self, text, dependencies=None):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp)
            path = src / 'library.ld'
            path.write_text(text)
            main = dict(metadata=dict(LIB='sample', _SHLIBDIR='/lib', SHLIB_NAME='libsample.so.1'),
                        shared_link_script=dict(template=dict(path='library.ld', sha256=digest(path)),
                                                substitutions={'@@SHLIB@@': '/lib/libsample.so.1', '@@LIBDIR@@': '/usr/lib'}))
            runtime = dict(metadata=dict(LIB='runtime', SHLIB_NAME='libruntime.so.2', SHLIB_LINK='libruntime.so',
                                         SHLIB_LDSCRIPT='', _LIBS='libruntime.a libruntime.so.2', _LIBDIR='/usr/lib'))
            return dynamic_group(main, [main, runtime], ['runtime'] if dependencies is None else dependencies, src)

    def test_declared_shared_members(self):
        self.assertTrue(self.check_group('GROUP ( @@SHLIB@@ @@LIBDIR@@/libruntime.so )\n'))

    def test_reject_undeclared_inputs_and_commands(self):
        for text in (
            'GROUP ( /lib/libsample.so.1 /tmp/libruntime.so )',
            'GROUP ( /lib/libsample.so.1 /usr/lib/libruntime.a )',
            'GROUP ( /usr/lib/libruntime.so /lib/libsample.so.1 )',
            'GROUP ( /lib/libsample.so.1 AS_NEEDED ( /usr/lib/libruntime.so ) )',
            'GROUP ( /lib/libsample.so.1 /usr/lib/libruntime.so ) INCLUDE extra.ld',
            'GROUP ( /lib/libsample.so.1 /usr/lib/libruntime.so /usr/lib/libruntime.so )',
            'INPUT ( /lib/libsample.so.1 /usr/lib/libruntime.so )',
        ):
            with self.subTest(script=text), self.assertRaises(ValueError):
                self.check_group(text)

    def test_reject_omitted_dependency(self):
        with self.assertRaises(ValueError):
            self.check_group('GROUP ( /lib/libsample.so.1 /usr/lib/libruntime.so )', [])


if __name__ == '__main__':
    unittest.main()
