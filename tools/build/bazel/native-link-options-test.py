#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Reject ambient linker searches while accepting declared dependency locations."""
from pathlib import Path
import tempfile
import unittest
from native_link_options import translate


class LinkDirectories(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name);self.src=root/'src';self.obj=root/'obj';self.src.mkdir();self.obj.mkdir()
        self.directory=self.obj/'custom-layout/dependency'
        self.record=dict(name='api',component='lib/api',dpadd=[str(self.obj/'sdk/usr/lib/libapi.a')])
        self.component=dict(library_dependencies=[self.record])
        self.selected=[dict(component='lib/api',metadata={'LIB':'api','.OBJDIR':str(self.directory)},library_dependencies=[])]
    def call(self,flags):return translate(self.component,self.selected,flags,self.src,self.obj)
    def test_explicit_object_directory_is_removed(self):
        self.assertEqual(self.call(['-Wl,-znow','-L'+str(self.directory),'-shared']),(['-Wl,-znow','-shared'],[str(self.directory)]))
    def test_declared_staged_artifact_directory(self):
        directory=str(Path(self.record['dpadd'][0]).parent)
        self.assertEqual(self.call(['-L',directory]),([],[directory]))
    def test_not_guessed_from_source_component(self):
        with self.assertRaisesRegex(ValueError,'lacks declared'):self.call(['-L'+str(self.obj/'lib/api')])
    def test_unknown_or_escaping_object_directory(self):
        self.selected[0]['metadata']['.OBJDIR']=str(self.src/'lib/api')
        with self.assertRaisesRegex(ValueError,'outside configured'):self.call([])
    def test_indirect_search_does_not_bypass_inventory(self):
        for flags in (['-Wl,-L,/usr/local/lib'],['--library-path=/usr/local/lib'],['-Xlinker','-L/usr/local/lib']):
            with self.subTest(flags=flags),self.assertRaisesRegex(ValueError,'indirect'):self.call(flags)
    def test_unmapped_source_link_input(self):
        with self.assertRaisesRegex(ValueError,'unmapped'):self.call(['-Wl,--version-script='+str(self.src/'map')])
    def test_transitive_object_directory(self):
        child=dict(name='child',component='lib/child',dpadd=[])
        self.selected[0]['library_dependencies']=[child]
        directory=self.obj/'nested/location'
        self.selected.append(dict(component='lib/child',metadata={'LIB':'child','.OBJDIR':str(directory)},library_dependencies=[]))
        self.assertEqual(self.call(['-L'+str(directory)]),([],[str(directory)]))


if __name__=='__main__':unittest.main()
