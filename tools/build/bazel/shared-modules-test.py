#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import copy
import unittest
import shared_modules

class SharedModuleInventory(unittest.TestCase):
    def setUp(self):
        self.component = dict(metadata=dict(LIB='', PROG='', SHLIB_NAME='module.so',
            SHLIB_NAME_FULL='module.so.full', SONAME='module.so', _LIBS='module.so',
            SOBJS='second.pico first.pico'))
        self.records = [dict(compile_contexts=dict(pic=dict(target=name+'.pico'))) for name in ('first','second')]
        self.labels = ['//:first.c', '//:second.cc']
        self.flags = {'//:first.c|pic':['-fpic'], '//:second.cc|pic':['-fpic','-std=c++17']}
    def check(self):
        return shared_modules.inventory(self.component,self.records,self.labels,self.flags)
    def test_preserves_declared_object_order_and_source_flags(self):
        order, flags = self.check()
        self.assertEqual(order, ['//:second.cc','//:first.c'])
        self.assertEqual(flags['//:second.cc'], ['-fpic','-std=c++17'])
    def test_requires_pic_only(self):
        self.records[0]['compile_contexts']['regular'] = dict(target='first.o')
        with self.assertRaises(ValueError): self.check()
    def test_rejects_missing_object(self):
        self.component['metadata']['SOBJS'] += ' missing.pico'
        with self.assertRaises(ValueError): self.check()
    def test_rejects_static_archive_substitute(self):
        self.component['metadata']['_LIBS'] += ' libmodule.a'
        with self.assertRaises(ValueError): self.check()
    def test_rejects_path_output(self):
        self.component['metadata']['SHLIB_NAME_FULL'] = '../module.so'
        with self.assertRaises(ValueError): self.check()
    def test_rejects_duplicate_objects(self):
        self.component['metadata']['SOBJS'] += ' first.pico'
        with self.assertRaises(ValueError): self.check()

if __name__ == '__main__': unittest.main()
