#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check alias resolution, ordering and rejection of unrepresented link semantics."""
import copy
import unittest
import tempfile
from pathlib import Path
from library_dependencies import resolve, shared_link_target, shared_link_labels, program_link_options, resolve_selections, component_link_labels


class Dependencies(unittest.TestCase):
    def setUp(self):
        self.component = {'metadata': {'LIBADD': 'thread_api cpp_api', 'LDADD': '-lpthread -lc++'},
                          'library_dependencies': [
                              {'name': 'thread_api', 'component': 'lib/thread_impl', 'ldadd': ['-lpthread']},
                              {'name': 'cpp_api', 'component': 'lib/cpp_impl', 'ldadd': ['-lc++']}]}
        self.selected = [{'component': 'lib/cpp_impl', 'metadata': {'LIB': 'c++'}},
                         {'component': 'lib/thread_impl', 'metadata': {'LIB': 'thr'}}]

    def test_aliases_preserve_link_order(self):
        self.assertEqual(resolve(self.component, self.selected), ['thr', 'c++'])

    def test_framework_dependency_is_explicit(self):
        self.component['framework_library_names']=['framework']
        self.component['library_dependencies'].insert(0,dict(name='framework',component='lib/framework',ldadd=['-lprivateframework']))
        self.component['metadata']['LDADD']='-lprivateframework -lpthread -lc++'
        self.selected.append(dict(component='lib/framework',metadata=dict(LIB='framework')))
        self.assertEqual(resolve(self.component,self.selected),['framework','thr','c++'])
        self.selected.pop()
        with self.assertRaisesRegex(ValueError,'not selected'):
            resolve(self.component,self.selected)

    def test_final_ldadd_order(self):
        self.component['metadata']['LDADD'] = '-lc++ -lpthread'
        self.assertEqual(resolve(self.component, self.selected), ['c++', 'thr'])

    def test_repeated_libraries_not_deduplicated(self):
        self.component['metadata']['LDADD'] = '-lc++ -lpthread -lc++'
        with self.assertRaisesRegex(ValueError, 'repeated libraries'):
            resolve(self.component, self.selected)

    def test_missing_component(self):
        with self.assertRaisesRegex(ValueError, 'not selected'):
            resolve(self.component, self.selected[:1])

    def test_reordered_inventory(self):
        self.component['library_dependencies'].reverse()
        with self.assertRaisesRegex(ValueError, 'order differs'):
            resolve(self.component, self.selected)

    def test_unrepresented_link_option(self):
        self.component['metadata']['LDADD'] += ' -Wl,--whole-archive'
        with self.assertRaisesRegex(ValueError, 'outside declared'):
            resolve(self.component, self.selected)

    def test_link_group_not_discarded(self):
        self.component['library_dependencies'][0]['ldadd'].insert(0, '-Wl,--start-group')
        self.component['metadata']['LDADD'] = '-Wl,--start-group -lpthread -lc++'
        with self.assertRaisesRegex(ValueError, 'explicit linker option support'):
            resolve(self.component, self.selected)

    def test_ambiguous_component(self):
        self.selected.append(copy.deepcopy(self.selected[0]))
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            resolve(self.component, self.selected)


class Linkage(unittest.TestCase):
    def setUp(self):
        self.static = dict(LIB='runtime', LIB_PRIVATE='', SHLIB_NAME='', _LIBS='libruntime.a libruntime_pic.a')
        self.shared = dict(LIB='api', LIB_PRIVATE='', SHLIB_NAME='libapi.so.2', _LIBS='libapi.a libapi.so.2')

    def test_static_archive_and_shared_selection(self):
        self.assertEqual(shared_link_target(self.static), 'runtime_shared_static')
        self.assertEqual(shared_link_target(self.shared), 'api_dynamic')
        components = [{'component':'lib/runtime','metadata': self.static}, {'component':'lib/api','metadata': self.shared}]
        self.assertEqual(shared_link_labels(['api', 'runtime'], components), ['//components/lib/api:api_dynamic', '//components/lib/runtime:runtime_shared_static'])

    def test_missing_regular_archive(self):
        self.static['_LIBS'] = 'libruntime_pic.a'
        with self.assertRaisesRegex(ValueError, 'regular archive'):
            shared_link_target(self.static)

    def test_static_only_configuration_retains_default_soname(self):
        self.shared['_LIBS'] = 'libapi.a'
        self.assertEqual(shared_link_target(self.shared), 'api_shared_static')

    def test_no_configured_linkable_output(self):
        self.shared['_LIBS'] = ''
        with self.assertRaisesRegex(ValueError, 'regular archive'):
            shared_link_target(self.shared)

    def test_private_archive(self):
        self.static.update(LIB_PRIVATE='private', _LIBS='libprivateruntime.a')
        self.assertEqual(shared_link_target(self.static), 'runtime_shared_static')

    def test_unselected_duplicate_names_do_not_reject_unique_dependency(self):
        components=[{'component':'lib/runtime','metadata': self.static}, {'component':'lib/runtime','metadata': self.static},
                    {'component':'lib/api','metadata': self.shared}]
        self.assertEqual(shared_link_labels(['api'],components),['//components/lib/api:api_dynamic'])
        with self.assertRaisesRegex(ValueError,'not selected'):
            shared_link_labels(['missing'],components)

    def test_duplicate_target(self):
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            shared_link_labels(['runtime'], [{'component':'lib/runtime','metadata': self.static}, {'component':'lib/runtime','metadata': self.static}])


class SearchPaths(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.src=self.root/'src';self.obj=self.root/'obj'
        self.src.mkdir();self.obj.mkdir();self.directory=self.obj/'lib/example'
        self.component=dict(metadata=dict(LIBADD='example',LDADD='-lexample',LDFLAGS=''),library_dependencies=[dict(name='example',component='lib/example',ldadd=['-lexample'],dpadd=[str(self.directory/'libexample.a')])])
        self.selected=[dict(component='lib/example',metadata=dict(LIB='example'))]
    def call(self,flags):
        self.component['metadata']['LDFLAGS']=flags
        return program_link_options(self.component,self.selected,self.src,self.obj)
    def test_accounted_search_preserves_other_flags(self):
        result,paths=self.call('-Wl,-znow -L'+str(self.directory)+' -pie')
        self.assertEqual(result,['-Wl,-znow','-pie']);self.assertEqual(paths,[str(self.directory)])
        self.assertEqual(self.call('-L '+str(self.directory)),([],paths))
    def test_unknown_directory_rejected(self):
        with self.assertRaisesRegex(ValueError,'lacks declared'):self.call('-L'+str(self.obj/'other'))
    def test_relative_and_traversal_rejected(self):
        for value in ('relative',str(self.directory/'../other')):
            with self.subTest(value=value),self.assertRaises(ValueError):self.call('-L'+value)
    def test_missing_dependency_rejected(self):
        self.selected=[]
        with self.assertRaisesRegex(ValueError,'not selected'):self.call('-L'+str(self.directory))
    def test_raw_object_link_input_rejected(self):
        with self.assertRaisesRegex(ValueError,'unmapped'):self.call(str(self.directory/'other.o'))
    def test_missing_search_argument(self):
        with self.assertRaisesRegex(ValueError,'missing library'):self.call('-L')


class ArchiveVariants(unittest.TestCase):
    def setUp(self):
        self.directory='/usr/obj/variant-check/lib/internal'
        self.record=dict(name='internal',component='lib/internal',ldadd=['-L'+self.directory,'-linternal_pie'],dpadd=[self.directory+'/libinternal_pie.a'])
        self.component=dict(metadata=dict(LIBADD='internal',LDADD=' '.join(self.record['ldadd'])),library_dependencies=[self.record])
        self.selected=[dict(component='lib/internal',metadata=dict(LIB='internal',LIB_PRIVATE='',_LIBS='libinternal.a libinternal_pie.a libinternal_pic.a',SHLIB_NAME='libinternal.so.1'))]
    def test_selected_pie_archive(self):
        self.assertEqual(resolve_selections(self.component,self.selected)[0]['variant'],'pie')
        self.assertEqual(component_link_labels(self.component,self.selected,dynamic=True),['//components/lib/internal:internal_pie_link'])
        self.assertEqual(component_link_labels(self.component,self.selected,dynamic=False),['//components/lib/internal:internal_pie_link'])
    def test_pic_variant(self):
        self.record['ldadd'][-1]='-linternal_pic';self.record['dpadd']=[self.directory+'/libinternal_pic.a']
        self.component['metadata']['LDADD']=' '.join(self.record['ldadd'])
        self.assertEqual(component_link_labels(self.component,self.selected,dynamic=True),['//components/lib/internal:internal_pic_link'])
    def test_nossp_variant(self):
        self.record['ldadd'][-1]='-linternal_nossp_pic'
        self.record['dpadd']=[self.directory+'/libinternal_nossp_pic.a']
        self.component['metadata']['LDADD']=' '.join(self.record['ldadd'])
        with self.assertRaisesRegex(ValueError,'not configured'):resolve(self.component,self.selected)
        self.selected[0]['metadata']['_LIBS']+=' libinternal_nossp_pic.a'
        for dynamic in (True,False):
            self.assertEqual(component_link_labels(self.component,self.selected,dynamic=dynamic),['//components/lib/internal:internal_nossp_pic_link'])
        self.record['dpadd']=[self.directory+'/libinternal_pic.a']
        with self.assertRaisesRegex(ValueError,'differs from declared DPADD'):resolve(self.component,self.selected)
    def test_variant_not_configured(self):
        self.selected[0]['metadata']['_LIBS']='libinternal.a'
        with self.assertRaisesRegex(ValueError,'not configured'):resolve(self.component,self.selected)
    def test_mismatched_artifact(self):
        self.record['dpadd']=[self.directory+'/libinternal.a']
        with self.assertRaisesRegex(ValueError,'differs from declared DPADD'):resolve(self.component,self.selected)
    def test_search_path_not_declared(self):
        self.record['ldadd'][0]='-L/usr/obj/other'
        with self.assertRaisesRegex(ValueError,'lacks declared'):resolve(self.component,self.selected)
    def test_changed_final_search_path(self):
        self.component['metadata']['LDADD']='-linternal_pie'
        with self.assertRaisesRegex(ValueError,'search paths differ'):resolve(self.component,self.selected)


if __name__ == '__main__':
    unittest.main()
