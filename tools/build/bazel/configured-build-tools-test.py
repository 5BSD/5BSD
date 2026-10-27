#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import json
from pathlib import Path
import tempfile
import unittest
from configured_build_tools import load
from libmd_environment import digest

class BuildTools(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.config=self.root/'tools.json'
        self.tool=self.root/'tool';self.tool.write_text('#!/bin/sh\nexit 0\n');self.tool.chmod(0o755)
    def check(self,data):
        self.config.write_text(json.dumps(data));inputs={}
        return load(self.config,inputs),inputs
    def test_explicit_executable_and_configuration_bound(self):
        arguments,inputs=self.check({'format':1,'tools':{'DTRACE':str(self.tool)}})
        self.assertEqual(arguments,['DTRACE='+str(self.tool.resolve())])
        self.assertEqual(inputs[str(self.tool)],digest(self.tool))
        self.assertEqual(inputs[str(self.config)],digest(self.config))
    def test_no_implicit_override(self):
        self.assertEqual(load(None,{}),[])
    def test_reject_schema_and_non_tool_variables(self):
        for data in ({'format':True,'tools':{}},{'format':1,'tools':{'CFLAGS':'-O0'}},{'format':1,'tools':{},'extra':0}):
            with self.subTest(data=data),self.assertRaises(ValueError):self.check(data)
    def test_reject_fragments_and_non_executables(self):
        for value in ('relative',str(self.tool)+' -G','/tmp/$(id)',str(self.tool)+';id'):
            with self.subTest(value=value),self.assertRaises(ValueError):self.check({'format':1,'tools':{'DTRACE':value}})
        self.tool.chmod(0o644)
        with self.assertRaises(ValueError):self.check({'format':1,'tools':{'DTRACE':str(self.tool)}})
if __name__=='__main__':unittest.main()
