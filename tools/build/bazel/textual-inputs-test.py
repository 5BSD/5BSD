#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify mixed standalone/textually included source action checks."""
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('checker',Path(__file__).with_name('textual-inputs-check.py'))
checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)

class TextualEdges(unittest.TestCase):
    def setUp(self):
        self.fragment='sources/reduction.c'
        self.consumer='sources/sin.c'
        self.inventory={self.fragment:dict(expected=set(),seen=0),self.consumer:dict(expected={self.fragment},seen=0)}
    def test_configured_standalone_fragment(self):
        checker.check_edges(self.fragment,[self.fragment],self.inventory,{self.fragment})
        checker.check_edges(self.consumer,[self.consumer,self.fragment],self.inventory,{self.fragment})
        self.assertEqual([v['seen'] for v in self.inventory.values()],[1,1])
    def test_missing_dependency(self):
        with self.assertRaises(ValueError):
            checker.check_edges(self.consumer,[self.consumer],self.inventory,{self.fragment})
    def test_undeclared_standalone_fragment(self):
        del self.inventory[self.fragment]
        with self.assertRaises(ValueError):
            checker.check_edges(self.fragment,[self.fragment],self.inventory,{self.fragment})
    def test_unrelated_textual_input(self):
        with self.assertRaises(ValueError):
            checker.check_edges(self.fragment,[self.fragment,'sources/other.c'],self.inventory,{self.fragment,'sources/other.c'})

if __name__=='__main__':unittest.main()
