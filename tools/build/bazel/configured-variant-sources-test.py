#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Reject ambiguous or unaccounted extra variant source mappings."""
import tempfile,unittest
from pathlib import Path
from configured_variant_sources import export

class Sources(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.source=self.root/'stub.c';self.source.write_text('void stub(void) {}\n')
        self.m=dict(LIB='fixture',SRCS='base.c',OBJS='base.o',SOBJS='stub.pico base.pico',PIEOBJS='',NOSSPSOBJS='',VARIANT_SOURCE_OBJECTS='stub.pico')
        self.values={'VARIANT_SOURCE.stub.pico':str(self.source)}
    def query(self,component,keys,extra):return {k:self.values[k] for k in keys}
    def export(self):return export(self.root,self.root,self.m,self.query,[],{})
    def test_shared_only_source(self):
        r=self.export();self.assertEqual(r[0]['objects'],['stub.pico']);self.assertEqual(r[0]['name'],'stub.c')
    def test_absent_or_ambiguous_object(self):
        self.m['SOBJS']='base.pico'
        with self.assertRaisesRegex(ValueError,'exactly one'):self.export()
        self.m['SOBJS']='stub.pico';self.m['OBJS']='stub.pico'
        with self.assertRaisesRegex(ValueError,'exactly one'):self.export()
    def test_redundant_source(self):
        self.m['SRCS']+=' stub.c'
        with self.assertRaisesRegex(ValueError,'conflicts'):self.export()
    def test_object_name_mismatch(self):
        other=self.root/'other.c';other.write_text('int other;');self.values['VARIANT_SOURCE.stub.pico']=str(other)
        with self.assertRaisesRegex(ValueError,'object name'):self.export()
    def test_external_origin(self):
        self.values['VARIANT_SOURCE.stub.pico']='/etc/passwd'
        with self.assertRaisesRegex(ValueError,'outside'):self.export()

if __name__=='__main__':unittest.main()
