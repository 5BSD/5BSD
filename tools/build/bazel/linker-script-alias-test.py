#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Validate library linker-script alias installation semantics."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('policy', Path(__file__).with_name('libmd-library-install-plan.py'))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class ScriptAliases(unittest.TestCase):
    def setUp(self):
        self.metadata = dict(SHLIB_LDSCRIPT_LINKS='libcompat.so libother.so',
            SHLIB_NAME='libexample.so.1', SHLIB_LINK='libexample.so',
            _LIBDIR='/usr/lib', LIBOWN='root', LIBGRP='wheel', LIBMODE='444',
            INSTALL='install -U', LSYMLINK='-l s -o root -g wheel -m 444',
            INSTALL_LIBSYMLINK='install -U -l s -o root -g wheel -m 444')

    def test_literal_aliases(self):
        self.assertEqual(policy.shared_script_aliases(self.metadata, {'output':'libexample.ld'}),
            [('libexample.so','/usr/lib/libcompat.so'),('libexample.so','/usr/lib/libother.so')])

    def test_absent_script_rejected(self):
        with self.assertRaisesRegex(ValueError, 'installed shared script'):
            policy.shared_script_aliases(self.metadata, None)

    def test_duplicate_self_and_path_aliases_rejected(self):
        for names in ('libcompat.so libcompat.so', 'libexample.so', '../libcompat.so', '/tmp/alias'):
            with self.subTest(names=names), self.assertRaises(ValueError):
                policy.shared_script_aliases(dict(self.metadata,SHLIB_LDSCRIPT_LINKS=names), {'output':'libexample.ld'})

    def test_altered_command_rejected(self):
        for name in ('LSYMLINK','INSTALL_LIBSYMLINK'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'installation command'):
                policy.shared_script_aliases(dict(self.metadata,**{name:'ln -s'}), {'output':'libexample.ld'})


if __name__ == '__main__':
    unittest.main()
