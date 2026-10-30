#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Reject RPC metadata that cannot be represented by the declared native action."""
import shlex,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from configured_rpc import export

class RPC(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.src=Path(self.temp.name);self.schema=self.src/'schema.x';self.schema.write_text('typedef int value;\n')
        self.compiler=self.src/'cpp';self.compiler.write_text('compiler')
        self.rpcgen=self.src/'rpcgen';self.rpcgen.write_text('generator')
        self.env=SimpleNamespace(compiler=self.compiler,resource=str(self.src/'resource'))
        self.values=dict(RPCGEN_OUTPUTS='schema.h schema_xdr.c',RPCGEN_TOOL='rpcgen',RPCGEN_FLAGS='-C',CPP='cpp -target test',PATH='/explicit')
        self.values['.OBJDIR']=str(self.src/'objects')
        self.values['RPCGEN']=shlex.join(['RPCGEN_CPP='+self.values['CPP'],'rpcgen','-C'])
        for name,mode,deps in [('schema.h','-h',''),('schema_xdr.c','-c','schema.h')]:
            self.values.update({'RPCGEN_SOURCE.'+name:str(self.schema),'RPCGEN_MODE.'+name:mode,'RPCGEN_DEPS.'+name:deps})
        self.lookup=patch('configured_rpc.shutil.which',side_effect=lambda name,path:str(self.src/name))
        self.lookup.start();self.addCleanup(self.lookup.stop)
    def query(self,component,keys,extra):return {k:self.values[k] for k in keys}
    def run_export(self):return export(self.src,self.src,self.env,self.query,[],{})
    def test_tool_and_output_dependencies(self):
        r=self.run_export();self.assertEqual(r['outputs'][1]['dependencies'],['schema.h'])
        self.assertEqual(r['tool']['path'],str(self.rpcgen))
    def test_recipe_override(self):
        self.values['.OBJDIR']=str(self.src/'objects')
        self.values['RPCGEN']='rpcgen -C'
        with self.assertRaisesRegex(ValueError,'recipe differs'):self.run_export()
    def test_unsupported_flags(self):
        self.values['RPCGEN_FLAGS']='-C -o override'
        with self.assertRaisesRegex(ValueError,'flag policy'):self.run_export()
    def test_mode_and_dependency_mismatch(self):
        for key,value in [('RPCGEN_MODE.schema.h','-c'),('RPCGEN_DEPS.schema.h','schema.h'),('RPCGEN_DEPS.schema.h','missing.h')]:
            old=self.values[key];self.values[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):self.run_export()
            self.values[key]=old
    def test_external_schema(self):
        self.values['RPCGEN_SOURCE.schema.h']='/etc/passwd'
        with self.assertRaisesRegex(ValueError,'maintained'):self.run_export()
    def test_preprocessor_identity(self):
        wrong=self.src/'wrong';wrong.write_text('other compiler');self.env.compiler=wrong
        with self.assertRaisesRegex(ValueError,'staged Clang'):self.run_export()

if __name__=='__main__':unittest.main()
