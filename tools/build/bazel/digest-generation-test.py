#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import tempfile
import unittest
from pathlib import Path
import configured_libmd

class DigestGeneration(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.src=Path(self.tmp.name)
        for name in ('script.sh','template.c','original.h'):(self.src/name).write_text('/* fixture */\n')
        self.values=dict(LIBMD_GENHL_SRCS='custom.c',LIBMD_GENHL_SCRIPT=str(self.src/'script.sh'),
            LIBMD_GENHL_TEMPLATE=str(self.src/'template.c'),LIBMD_HEADER_ALIASES='nested/custom.h',
            LIBMD_GEN_SH='/bin/sh',LIBMD_GEN_SED='/bin/sh',LIBMD_GEN_MV='/bin/sh',LIBMD_GEN_RM='/bin/sh',PATH='/bin:/usr/bin')
        self.values.update({'LIBMD_GENHL_ARGS.custom.c':'7 custom CUSTOM_ -',
                            'LIBMD_HEADER_SOURCE.nested/custom.h':str(self.src/'original.h')})
    def query(self,component,keys,extra):return {k:self.values[k] for k in keys}
    def export(self):return configured_libmd.export(self.src,self.src,self.query,[],{})
    def test_declared_names_and_inputs(self):
        result=self.export()
        self.assertEqual(result['outputs'],[dict(name='custom.c',arguments=['7','custom','CUSTOM_','-'])])
        self.assertEqual(result['headers'][0]['source']['path'],'original.h')
    def test_invalid_output_header_and_arguments(self):
        for key,value in [('LIBMD_GENHL_SRCS','../bad.c'),('LIBMD_HEADER_ALIASES','../bad.h'),
                          ('LIBMD_GENHL_ARGS.custom.c','7 bad-name CUSTOM_ -')]:
            saved=self.values[key];self.values[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.export()
            self.values[key]=saved
    def test_external_origin_rejected(self):
        self.values['LIBMD_HEADER_SOURCE.nested/custom.h']='/etc/passwd'
        with self.assertRaisesRegex(ValueError,'outside source'):self.export()
    def test_tools_must_match_sdk(self):
        result=self.export()
        with self.assertRaisesRegex(ValueError,'staged SDK'):
            configured_libmd.emit(dict(metadata=dict(LIB='example'),digest_generation=result),
                                  dict(tool_origins={},inputs={}),self.src,self.src,lambda p:str(p),lambda *a,**k:None,{})
    def test_changed_metadata_rejected(self):
        calls=[]
        def query(component,keys,extra):
            calls.append(1)
            result=self.query(component,keys,extra)
            if len(calls)==3:result['LIBMD_GENHL_SRCS']='other.c'
            return result
        with self.assertRaisesRegex(ValueError,'changed'):
            configured_libmd.export(self.src,self.src,query,[],{})

if __name__=='__main__':unittest.main()
