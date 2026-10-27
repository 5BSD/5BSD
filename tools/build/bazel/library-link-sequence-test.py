#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Preserve Make's final aliases, library order and repeated archive references."""
import copy
import unittest
from library_link_sequence import resolve, artifacts


def library(name, deps=()):
    return dict(component='lib/'+name, metadata=dict(LIB=name,LIB_PRIVATE='private',LIBADD=' '.join(d['name'] for d in deps),LDADD=' '.join(flag for d in deps for flag in d['ldadd']),_LIBS='libprivate'+name+'.a',SHLIB_NAME=''),library_dependencies=list(deps))


def dependency(name, flags=None, archives=None):
    return dict(name=name,component='lib/'+name,ldadd=flags or ['-lprivate'+name],dpadd=archives or ['/obj/libprivate'+name+'.a'])


class Sequences(unittest.TestCase):
    def setUp(self):
        self.c=dependency('c');self.cxx=dependency('cxx',['-lprivatecxx','-lprivatec'],['/obj/libprivatecxx.a','/obj/libprivatec.a'])
        self.component=dict(metadata=dict(LIB='',LIBADD='cxx c',LDADD='-lprivatecxx -lprivatec -lprivatec'),library_dependencies=[self.cxx,self.c])
        self.components=[library('cxx',[self.c]),library('c')]

    def test_compound_alias_and_repetition(self):
        entries=resolve(self.component,self.components)
        self.assertEqual([e['library'] for e in entries],['cxx','c','c'])
        self.assertEqual(artifacts(entries,self.components),['//components/lib/cxx:cxx','//components/lib/c:c','//components/lib/c:c'])

    def test_transitive_mapping_without_duplicate_root_record(self):
        self.component['metadata'].update(LIBADD='cxx',LDADD='-lprivatecxx -lprivatec')
        self.component['library_dependencies']=[self.cxx]
        self.assertEqual([e['library'] for e in resolve(self.component,self.components)],['cxx','c'])

    def test_reordered_final_sequence_preserved(self):
        self.component['metadata']['LDADD']='-lprivatec -lprivatecxx -lprivatec'
        self.assertEqual([e['library'] for e in resolve(self.component,self.components)],['c','cxx','c'])

    def test_unknown_omitted_and_group_flags_rejected(self):
        for flags in ('-lprivatecxx','-lprivatecxx -lprivatec -lunknown','-Wl,--start-group -lprivatecxx -lprivatec -Wl,--end-group'):
            with self.subTest(flags=flags),self.assertRaises(ValueError):
                resolve(dict(self.component,metadata=dict(self.component['metadata'],LDADD=flags)),self.components)

    def test_missing_source_and_archive_identity(self):
        with self.assertRaisesRegex(ValueError,'not selected'):resolve(self.component,self.components[:1])
        self.cxx['dpadd']=['/obj/libprivatec.a']
        with self.assertRaisesRegex(ValueError,'archive identity'):resolve(self.component,self.components)

    def test_compound_requires_transitive_mapping(self):
        self.component['metadata'].update(LIBADD='cxx',LDADD='-lprivatecxx -lprivatec')
        self.component['library_dependencies']=[self.cxx]
        self.components[0]['library_dependencies']=[]
        with self.assertRaisesRegex(ValueError,'transitive source mapping'):resolve(self.component,self.components)

    def test_simple_alias_uses_declared_source_identity(self):
        dep=dependency('threads',['-lpthread'],['/obj/libpthread.a'])
        component=dict(metadata=dict(LIBADD='threads',LDADD='-lpthread -lpthread'),library_dependencies=[dep])
        self.assertEqual([e['library'] for e in resolve(component,[library('threads')])],['threads','threads'])

    def test_same_alias_with_context_specific_search_paths(self):
        self.components[0]['library_dependencies']=[copy.deepcopy(self.c)]
        self.c['ldadd']=['-L/obj','-lprivatec']
        self.component['metadata']['LDADD']='-lprivatecxx -L/obj -lprivatec -lprivatec'
        entries=resolve(self.component,self.components)
        self.assertEqual([e['library'] for e in entries],['cxx','c','c'])
        self.assertEqual(entries[1]['search_directories'],['/obj'])

    def test_repeated_shared_libraries_have_one_runtime_identity_each(self):
        from configured_tests import runtime_libraries
        for candidate in self.components:
            name=candidate['metadata']['LIB']
            soname='libprivate'+name+'.so.1'
            candidate['metadata']['SHLIB_NAME']=soname
            candidate['metadata']['_LIBS']+=' '+soname
        runtime=runtime_libraries(self.component,self.components)
        self.assertEqual(set(runtime),{'libprivatecxx.so.1','libprivatec.so.1'})

    def test_resolved_selection_retains_source_component(self):
        entries=resolve(self.component,self.components)
        self.assertEqual([entry['component'] for entry in entries],
                         ['lib/cxx','lib/c','lib/c'])

    def test_same_basename_different_component_alias_is_rejected(self):
        # One transitive dependency and one direct dependency use the same
        # linker alias, but point to distinct libraries. Basenames and archive
        # variants alone must not cause these identities to be merged.
        other=library('c')
        other['component']='stand/c'
        transitive=copy.deepcopy(self.c)
        transitive['component']=other['component']
        self.components[0]['library_dependencies']=[transitive]
        self.components.append(other)
        with self.assertRaisesRegex(ValueError,'ambiguous native library alias'):
            resolve(self.component,self.components)

    def test_artifact_kind_follows_selected_source_not_last_basename(self):
        from library_dependencies import component_link_labels
        shared=library('c')
        shared['metadata'].update(SHLIB_NAME='libprivatec.so.1',
                                 _LIBS='libprivatec.a libprivatec.so.1')
        static=library('c')
        static['component']='stand/c'
        consumer=dict(metadata=dict(LIBADD='c',LDADD='-lprivatec'),
                      library_dependencies=[self.c])
        for components in ([shared,static],[static,shared]):
            with self.subTest(order=[c['component'] for c in components]):
                entries=resolve(consumer,components)
                self.assertEqual(artifacts(entries,components),['//components/lib/c:c_soname'])
                self.assertEqual(component_link_labels(consumer,components,dynamic=True),
                                 ['//components/lib/c:c_dynamic'])
                self.assertEqual(component_link_labels(consumer,components,dynamic=True,sequence=True),
                                 ['//components/lib/c:c_dynamic'])
                consumer['library_dependencies'][0]=dict(self.c,component='stand/c')
                self.assertEqual(artifacts(resolve(consumer,components),components),['//components/stand/c:c'])
                self.assertEqual(component_link_labels(consumer,components,dynamic=True),
                                 ['//components/stand/c:c_shared_static'])
                consumer['library_dependencies'][0]=self.c

    def test_artifact_identity_mismatch_and_duplicate_component_rejected(self):
        entries=resolve(self.component,self.components)
        entries[0]['component']='lib/c'
        with self.assertRaisesRegex(ValueError,'name differs'):
            artifacts(entries,self.components)
        entries[0]['component']='missing'
        with self.assertRaisesRegex(ValueError,'not selected'):
            artifacts(entries,self.components)
        with self.assertRaisesRegex(ValueError,'ambiguous library component'):
            artifacts([],self.components+[copy.deepcopy(self.components[0])])

    def test_no_input_mutation(self):
        before=copy.deepcopy((self.component,self.components))
        resolve(self.component,self.components)
        self.assertEqual((self.component,self.components),before)


if __name__=='__main__':unittest.main()
