#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check alias origin validation and changing configuration rejection."""
import tempfile,unittest
from pathlib import Path
from configured_source_aliases import export
from libmd_environment import digest

class Aliases(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.src=Path(self.temp.name);self.origin=self.src/'original.c';self.origin.write_text('int value;\n')
        self.values={'SOURCE_ALIAS.renamed.c':str(self.origin),'SOURCE_ALIAS.ordinary.c':''}
    def query(self,component,keys,extra):return {k:self.values[k] for k in keys}
    def test_explicit_alias_with_unchanged_ordinary_source(self):
        inputs={};r=export(self.src,self.src,['renamed.c','ordinary.c'],self.query,[],inputs)
        self.assertEqual(set(r),{'renamed.c'})
        self.assertEqual(r['renamed.c']['path'],'original.c')
        self.assertEqual(inputs,{str(self.origin):digest(self.origin)})
    def test_invalid_name(self):
        for name in ('../renamed.c','sub/renamed.c','renamed.h'):
            self.values['SOURCE_ALIAS.'+name]=str(self.origin)
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'basename'):
                export(self.src,self.src,[name],self.query,[],{})
    def test_relative_or_external_origin(self):
        for value in ('original.c','/etc/passwd'):
            self.values['SOURCE_ALIAS.renamed.c']=value
            with self.subTest(value=value),self.assertRaises(ValueError):
                export(self.src,self.src,['renamed.c'],self.query,[],{})
    def test_symlink_escape(self):
        p=self.src/'escape.c';p.symlink_to('/etc/passwd');self.values['SOURCE_ALIAS.renamed.c']=str(p)
        with self.assertRaisesRegex(ValueError,'outside'):export(self.src,self.src,['renamed.c'],self.query,[],{})
    def test_changed_configuration(self):
        calls=[]
        def query(component,keys,extra):
            calls.append(1)
            return {'SOURCE_ALIAS.renamed.c':str(self.origin) if len(calls)==1 else ''}
        with self.assertRaisesRegex(ValueError,'changed'):export(self.src,self.src,['renamed.c'],query,[],{})

if __name__=='__main__':unittest.main()
