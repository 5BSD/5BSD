#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Composition must preserve source bindings and reject ambiguous graphs."""
import json,tempfile,unittest
from pathlib import Path
from component_plans import load
from libmd_environment import digest

class Plans(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.source=self.root/'source';self.source.mkdir()
        self.shared=self.source/'profile';self.shared.write_text('target configuration')
    def plan(self,name,component,**changes):
        inputs={str(self.shared):digest(self.shared)}
        data=dict(format=1,status='configured',components=[dict(component=component,program_override=None)],input_sha256=inputs,
            execution_tool_overrides=[],build_environment=dict(component=str(self.source/component),target='native',objtop='/usr/obj/test',profile=str(self.shared),input_sha256=dict(inputs),make_include_closure=dict(inputs),commands=[]))
        data.update(changes);p=self.root/name;p.write_text(json.dumps(data));return p
    def test_union_preserves_all_plans(self):
        a=self.plan('a','lib/a');b=self.plan('b','lib/b');before=[digest(a),digest(b)]
        result=load([a,b],self.source)
        self.assertEqual([r['component'] for r in result['components']],['lib/a','lib/b'])
        self.assertEqual([digest(a),digest(b)],before)
        self.assertEqual(result['input_sha256'][str(a)],before[0])
        self.assertEqual(len(result['component_plans']),2)
    def test_duplicate_record(self):
        with self.assertRaisesRegex(ValueError,'duplicate component'):
            load([self.plan('a','lib/a'),self.plan('b','lib/a')],self.source)
    def test_duplicate_file(self):
        p=self.plan('a','lib/a')
        with self.assertRaisesRegex(ValueError,'unique component'):load([p,p],self.source)
    def test_changed_input(self):
        p=self.plan('a','lib/a');self.shared.write_text('changed')
        with self.assertRaisesRegex(ValueError,'input changed'):load([p],self.source)
    def test_conflicting_binding(self):
        a=self.plan('a','lib/a');self.shared.write_text('different');b=self.plan('b','lib/b')
        with self.assertRaisesRegex(ValueError,'conflicting component input'):load([a,b],self.source)
    def test_environment_mismatch(self):
        a=self.plan('a','lib/a');b=self.plan('b','lib/b');data=json.loads(b.read_text());data['build_environment']['target']='other';b.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'different build environments'):load([a,b],self.source)
    def test_source_root_mismatch(self):
        p=self.plan('a','lib/a')
        with self.assertRaisesRegex(ValueError,'source root mismatch'):load([p],self.root/'different')
    def test_unbound_environment_input(self):
        p=self.plan('a','lib/a');data=json.loads(p.read_text());data['input_sha256']={};p.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'missing from component bindings'):load([p],self.source)
    def test_tool_selection_mismatch(self):
        a=self.plan('a','lib/a');b=self.plan('b','lib/b',execution_tool_overrides=['CC=different'])
        with self.assertRaisesRegex(ValueError,'different build environments'):load([a,b],self.source)

if __name__=='__main__':unittest.main()
