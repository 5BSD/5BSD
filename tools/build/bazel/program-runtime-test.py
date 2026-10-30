#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Explicit native program runtimes must reach both linkage and load checks."""
import unittest
from library_dependencies import program_runtime_labels, program_runtime_selections
from configured_tests import runtime_libraries


def library(name, deps=(), shared=True):
    return dict(component='lib/'+name, metadata=dict(LIB=name, LIB_PRIVATE='',
        LIBADD=' '.join(deps),LDADD=' '.join('-l'+d for d in deps),
        SHLIB_NAME='lib'+name+'.so.1' if shared else '',
        _LIBS='lib'+name+'.a'+(' lib'+name+'.so.1' if shared else '')),
        library_dependencies=[dict(name=d,component='lib/'+d,ldadd=['-l'+d]) for d in deps])

class ProgramRuntime(unittest.TestCase):
    def setUp(self):
        self.runtime=library('runtime',['syscalls'])
        self.syscalls=library('syscalls')
        self.program=dict(metadata=dict(LIB='',LIBADD='',LDADD=''),library_dependencies=[])
        self.components=[self.program,self.runtime,self.syscalls]
    def test_no_implicit_selection(self):
        self.assertEqual(program_runtime_labels([],self.components,[]),[])
        self.assertEqual(runtime_libraries(self.program,self.components),{})
    def test_declared_runtime_and_transitive_identity(self):
        self.assertEqual(program_runtime_labels(['runtime'],self.components,[]),['//components/lib/runtime:runtime_dynamic'])
        result=runtime_libraries(self.program,self.components,program_runtimes=['runtime'])
        self.assertEqual(set(result),{'libruntime.so.1','libsyscalls.so.1'})
    def test_bad_selection_rejected(self):
        for names in ('runtime',['runtime','runtime'],['absent'],[1]):
            with self.subTest(names=names),self.assertRaises(ValueError):
                program_runtime_selections(names,self.components)
        with self.assertRaisesRegex(ValueError,'ambiguous'):
            program_runtime_selections(['runtime'],self.components+[self.runtime])
    def test_unrelated_same_names_do_not_hide_selected_source(self):
        other=library('syscalls',shared=False)
        other['component']='stand/syscalls'
        for components in (self.components+[other],[other]+self.components):
            selected=program_runtime_selections(['runtime'],components)
            self.assertEqual(selected[0]['component'],'lib/runtime')
            self.assertEqual(program_runtime_labels(['runtime'],components,[]),['//components/lib/runtime:runtime_dynamic'])
            runtime=runtime_libraries(self.program,components,program_runtimes=['runtime'])
            self.assertEqual(runtime['libsyscalls.so.1']['component'],'lib/syscalls')
            with self.assertRaisesRegex(ValueError,'ambiguous program runtime'):
                program_runtime_selections(['syscalls'],components)

    def test_same_soname_from_distinct_sources_is_rejected(self):
        other=library('syscalls')
        other['component']='stand/syscalls'
        program=dict(metadata=dict(LIB='',LIBADD='syscalls alternate',
                                   LDADD='-lsyscalls -lalternate'),
                     library_dependencies=[
                         dict(name='syscalls',component='lib/syscalls',ldadd=['-lsyscalls']),
                         dict(name='alternate',component='stand/syscalls',ldadd=['-lalternate'])])
        with self.assertRaisesRegex(ValueError,'ambiguous runtime SONAME'):
            runtime_libraries(program,[self.syscalls,other])

    def test_custom_linkage_not_silently_ignored(self):
        for flag in ('-static','-nostdlib','-nodefaultlibs','-nolibc','-Wl,-Bstatic','-Wl,-static','-static-pie','-Wl,--no-dynamic-linker'):
            with self.subTest(flag=flag),self.assertRaisesRegex(ValueError,'dynamic linkage'):
                program_runtime_labels(['runtime'],self.components,[flag])
    def test_group_archive_runtime_dependency(self):
        self.runtime['shared_link_script']={'template':'test-only'}
        archive=library('nonshared',['extra'],False)
        extra=library('extra');self.components += [archive,extra]
        groups={'lib/runtime':[dict(component='lib/runtime',library='runtime',kind='shared',variant=None),dict(component='lib/nonshared',library='nonshared',kind='archive',variant='regular')]}
        result=runtime_libraries(self.program,self.components,groups=groups,program_runtimes=['runtime'])
        self.assertEqual(set(result),{'libruntime.so.1','libsyscalls.so.1','libextra.so.1'})

if __name__=='__main__':unittest.main()
