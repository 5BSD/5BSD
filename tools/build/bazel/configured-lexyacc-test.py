#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check generator metadata boundaries, including unmodeled outputs."""
import tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from configured_lexyacc import export,emit

class Generators(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        for n in ('scan.l','parse.y','lex','yacc','m4'):(self.root/n).write_text(n)
        self.values={'LEX_OUTPUTS':'scan.c','YACC_OUTPUTS':'parse.c','LEX':'lex','LEX_M4':'m4','YACC':'yacc','PATH':'/explicit','.PATH':str(self.root),'.OBJDIR':str(self.root/'objects'),'LEX_SOURCE.scan.c':'scan.l','LEX_FLAGS.scan.c':'-Pprefix','YACC_SOURCE.parse.c':'parse.y','YACC_FLAGS.parse.c':'-d -pprefix','YACC_HEADER.parse.c':'parse.h','YACC_STYLE.parse.c':'named'}
        lookup=patch('configured_lexyacc.shutil.which',side_effect=lambda name,path:str(self.root/name));lookup.start();self.addCleanup(lookup.stop)
    def query(self,component,keys,extra):return {k:self.values[k] for k in keys}
    def export(self):return export(self.root,self.root,None,self.query,[],{})
    def test_named_outputs_and_headerless_profile(self):
        r=self.export();self.assertEqual(set(r['tools']),{'lex','yacc','m4'})
        self.assertEqual(r['generators'][1]['header'],'parse.h')
        self.values['YACC_FLAGS.parse.c']='-pprefix';self.values['YACC_HEADER.parse.c']=''
        self.assertEqual(self.export()['generators'][1]['header'],'')
    def test_traditional_outputs_rejected(self):
        self.values['YACC_STYLE.parse.c']='traditional'
        with self.assertRaisesRegex(ValueError,'traditional'):self.export()
    def test_unmodeled_outputs_rejected(self):
        for flag in ('-v','-o','--header-file=other.h','-Sother.skel'):
            self.values['LEX_FLAGS.scan.c']=flag
            with self.subTest(flag=flag),self.assertRaisesRegex(ValueError,'additional'):self.export()
    def test_header_flag_mismatch(self):
        self.values['YACC_FLAGS.parse.c']='-pprefix'
        with self.assertRaisesRegex(ValueError,'header differs'):self.export()
    def test_missing_staged_tool_rejected(self):
        c=dict(metadata=dict(LIB='test',PROG=''),lexyacc_generation=self.export())
        with self.assertRaisesRegex(ValueError,'staged SDK'):
            emit(c,dict(tool_origins={},inputs={}),self.root,None,None)

if __name__=='__main__':unittest.main()
