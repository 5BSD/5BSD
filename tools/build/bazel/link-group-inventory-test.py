#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Policy checks for typed linker GROUP inventory; not native link tests."""
from pathlib import Path
import tempfile
import unittest
from libmd_environment import digest
from link_group_inventory import resolve

class GroupInventory(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.src = Path(self.tmp.name)
        self.template = self.src / 'sample.ld'
        self.main = self.component('sample', 'libsample.a libsample.so.1', 'libsample.so.1')
        self.main['metadata']['SHLIB_LDSCRIPT'] = 'sample.ld'
        self.archive = self.component('nonshared', 'libnonshared.a', '')
        self.runtime = self.component('runtime', 'libruntime.a libruntime.so.2', 'libruntime.so.2')
        self.components = [self.main, self.archive, self.runtime]

    def component(self, name, outputs, shared):
        return dict(component='lib/'+name,metadata=dict(LIB=name, LIB_PRIVATE='', _LIBS=outputs,
            _LIBDIR='/usr/lib', _SHLIBDIR='/lib', SHLIB_NAME=shared,
            SHLIB_LINK='lib'+name+'.so' if shared else '', SHLIB_LDSCRIPT=''))

    def check(self, text):
        self.template.write_text(text)
        self.main['shared_link_script'] = dict(template=dict(path='sample.ld',
            sha256=digest(self.template)), substitutions={'@@SHLIB@@':'/lib/libsample.so.1', '@@LIBDIR@@':'/usr/lib'})
        return resolve(self.main, self.components, self.src)

    def test_mixed_order(self):
        items = self.check('GROUP ( @@SHLIB@@ @@LIBDIR@@/libnonshared.a @@LIBDIR@@/libruntime.so )')
        self.assertEqual([(i['library'],i['kind'],i['variant']) for i in items],
            [('sample','shared',None),('nonshared','archive','regular'),('runtime','shared',None)])

    def test_variants_follow_output_inventory(self):
        self.archive['metadata']['_LIBS'] += ' libnonshared_nossp_pic.a'
        items = self.check('GROUP ( @@SHLIB@@ /usr/lib/libnonshared_nossp_pic.a )')
        self.assertEqual(items[1]['variant'], 'nossp_pic')

    def test_reject_unselected_or_unbuilt(self):
        for member in ('/tmp/libnonshared.a', '/usr/lib/libmissing.a', '/usr/lib/libnonshared_pic.a', '/usr/lib/../lib/libnonshared.a'):
            with self.subTest(member=member), self.assertRaises(ValueError):
                self.check('GROUP ( @@SHLIB@@ '+member+' )')

    def test_reject_commands_reordering_and_repetition(self):
        for text in ('INPUT ( @@SHLIB@@ )', 'GROUP ( @@SHLIB@@ AS_NEEDED ( /usr/lib/libruntime.so ) )',
                     'GROUP ( /usr/lib/libnonshared.a @@SHLIB@@ )', 'GROUP ( @@SHLIB@@ @@SHLIB@@ )',
                     'GROUP ( @@SHLIB@@ /lib/libruntime.so.2 /usr/lib/libruntime.so )'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.check(text)

    def test_nested_script_not_treated_as_alias(self):
        self.runtime['metadata']['SHLIB_LDSCRIPT'] = 'other.ld'
        with self.assertRaises(ValueError):
            self.check('GROUP ( @@SHLIB@@ /usr/lib/libruntime.so )')

    def test_duplicate_library_rejected(self):
        self.components.append(self.archive)
        with self.assertRaises(ValueError):
            self.check('GROUP ( @@SHLIB@@ /usr/lib/libnonshared.a )')

if __name__ == '__main__':
    unittest.main()
