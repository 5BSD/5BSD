#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check metadata-derived symlink semantics before stage reconciliation."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('policy', Path(__file__).with_name('libmd-library-install-plan.py'))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class Symlinks(unittest.TestCase):
    def setUp(self):
        self.metadata = dict(SYMLINKS='library.a /usr/lib/alias.a ../lib/tool /usr/bin/tool',
                             _SYMLINKOWN='root', _SYMLINKGRP='wheel', _SYMLINKMODE='755',
                             INSTALL='install -U', SYMLINK='-l s -o root -g wheel -m 755',
                             INSTALL_SYMLINK='install -U -l s -o root -g wheel -m 755')

    def test_literal_targets(self):
        self.assertEqual(policy.configured_symlinks(self.metadata),
                         [('library.a', '/usr/lib/alias.a'), ('../lib/tool', '/usr/bin/tool')])
        self.metadata['SYMLINKS'] = '/lib/library.so /usr/lib/library.so'
        self.assertEqual(policy.configured_symlinks(self.metadata), [('/lib/library.so', '/usr/lib/library.so')])

    def test_invalid_mapping(self):
        for value in ('target', 'target relative/destination', 'target /usr/../etc/file',
                      "'a b' /usr/lib/link", "'$LIB' /usr/lib/link"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.configured_symlinks(dict(self.metadata, SYMLINKS=value))

    def test_custom_command_rejected(self):
        for key in ('SYMLINK', 'INSTALL_SYMLINK'):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'command'):
                policy.configured_symlinks(dict(self.metadata, **{key:'install -l rs'}))


if __name__ == '__main__':
    unittest.main()
