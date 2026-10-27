#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Validate configured program object membership, order and linker selection."""
import unittest
import program_compile


class ProgramCompilation(unittest.TestCase):
    def test_object_order_and_per_source_flags(self):
        records=[dict(name='a.c',compile_contexts={'pie':dict(target='a.pieo')}),
                 dict(name='b.cc',compile_contexts={'regular':dict(target='b.o')})]
        component=dict(metadata=dict(OBJS='b.o a.pieo'))
        order,flags=program_compile.inventory(component,records,['a.c','b.cc'],{'a.c|pie':['-fpie','-DA'], 'b.cc|regular':['-DB']})
        self.assertEqual(order,['b.cc','a.c'])
        self.assertEqual(flags,{'a.c':['-fpie','-DA'],'b.cc':['-DB']})

    def test_missing_and_duplicate_objects_rejected(self):
        record=dict(name='a.c',compile_contexts={'regular':dict(target='a.o')})
        for objects in ('', 'a.o a.o', 'a.o missing.o', 'other.o'):
            with self.subTest(objects=objects), self.assertRaises(ValueError):
                program_compile.inventory(dict(metadata=dict(OBJS=objects)),[record],['a.c'],{'a.c|regular':[]})

    def test_missing_or_ambiguous_context_rejected(self):
        for contexts in ({},{'regular':dict(target='a.o'),'pie':dict(target='a.pieo')}, {'pic':dict(target='a.pico')}):
            with self.subTest(contexts=contexts), self.assertRaises(ValueError):
                program_compile.inventory(dict(metadata=dict(OBJS='a.o')),[dict(name='a.c',compile_contexts=contexts)],['a.c'],{})

    def test_driver_follows_make_program_selector(self):
        self.assertEqual(program_compile.link_driver(dict(PROG='test',PROG_CXX='test')),('g++','CXXFLAGS'))
        self.assertEqual(program_compile.link_driver(dict(PROG='test',PROG_CXX='')),('gcc','CFLAGS'))
        with self.assertRaises(ValueError):program_compile.link_driver(dict(PROG='test',PROG_CXX='other'))


if __name__=='__main__':
    unittest.main()
