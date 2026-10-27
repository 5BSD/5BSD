#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compare exported generators with real maintained Make outputs, without Bazel."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
import tempfile
import shutil
import time
import sys
from libmd_environment import BuildEnvironment, digest
from libmd_paths import rewrite_includes

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--asm-plan', type=Path, required=True)
p.add_argument('--c-plan', type=Path, required=True)
a = p.parse_args()

class MaintainedGraph(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plans = [(path, json.loads(path.read_text())) for path in [a.asm_plan, a.c_plan]]

    def test_all_generators_match_maintained_make(self):
        for path, plan in self.plans:
            work = path.parent / 'workspace'
            results = path.parent / 'generator-results'
            results.mkdir(exist_ok=True)
            recorded=plan['build_environment']
            buildenv=BuildEnvironment(Path(plan['source_root']),Path(recorded['objtop']),Path(recorded['profile']),Path(plan['make']),Path(recorded['component']))
            buildenv.query([g['output'] for g in plan['generators']],obj=path.parent/'query-obj',extra=plan['component_overrides'])
            original = BuildEnvironment(Path(plan['source_root']),Path(recorded['objtop']),Path(recorded['profile']),Path(plan['make']))
            reference = path.parent/'original-reference';reference.mkdir(exist_ok=True)
            original.query([g['output'] for g in plan['generators']],obj=reference,extra=plan['component_overrides'])
            for gen in plan['generators']:
                with self.subTest(profile=path.parent.name, output=gen['output']):
                    output = results / gen['output']
                    command=['/bin/sh',str(work/gen['script'])]+gen['arguments']+[str(work/gen['template'])]
                    if gen['copyright'] is not None:command.append(str(work/gen['copyright']))
                    command += [str(output),'/usr/bin/sed']
                    if gen['kind']=='manual':command.append('/bin/cat')
                    command += ['/bin/mv','/bin/rm']
                    subprocess.run(command,check=True)
                    self.assertEqual(output.read_bytes(), (path.parent / 'query-obj' / gen['output']).read_bytes())
                    self.assertEqual(output.read_bytes(), (reference / gen['output']).read_bytes())

    def test_source_snapshots_bind_exact_maintained_inputs(self):
        for planpath,plan in self.plans:
            for name,expected in plan['snapshot_sha256'].items():
                self.assertEqual(hashlib.sha256((planpath.parent/'workspace'/name).read_bytes()).hexdigest(),expected,name)
            for name,digest in plan['source_sha256'].items():
                self.assertEqual(hashlib.sha256((Path(plan['source_origins'][name])).read_bytes()).hexdigest(),digest,name)

    def test_complete_source_selection_and_profile_invalidation(self):
        asm, portable = [r for _,r in self.plans]
        for plan in (asm,portable):
            self.assertEqual({s['name'] for s in plan['sources']},set(plan['metadata']['SRCS'].split())-{'sys/md5.h'})
        self.assertTrue(any(s['name'].endswith('.S') for s in asm['sources']))
        self.assertFalse(any(s['name'].endswith('.S') for s in portable['sources']))
        self.assertNotEqual(asm['metadata']['CFLAGS'],portable['metadata']['CFLAGS'])
        self.assertEqual(asm['per_file_flags']['skein_block.c'],'-DSKEIN_LOOP=995')
        self.assertIn('-DSKEIN_LOOP=0',asm['metadata']['ACFLAGS'])

    def test_generated_input_change_changes_output(self):
        path,plan=self.plans[0]
        gen=next(g for g in plan['generators'] if g['output']=='md4hl.c')
        work=path.parent/'workspace'; template=work/gen['template']
        before=template.read_bytes(); output=path.parent/'changed-md4hl.c'
        try:
            template.write_bytes(before+b'\n/* declared-input-invalidation */\n')
            subprocess.run(['/bin/sh',str(work/gen['script'])]+gen['arguments']+[str(template),str(output),'/usr/bin/sed','/bin/mv','/bin/rm'],check=True)
            self.assertIn(b'declared-input-invalidation',output.read_bytes())
        finally:
            template.write_bytes(before)

    def test_new_include_directory_preserves_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary); src=base/'src'; obj=base/'obj'
            (src/'new/header-dir').mkdir(parents=True);obj.mkdir()
            tokens=['-DFIRST','-I.', '-I', str(src/'new/header-dir'), '-DLAST']
            flags,dirs=rewrite_includes(tokens,src,obj)
            self.assertEqual(flags,['-DFIRST','-I.','-I','sources/new/header-dir','-DLAST'])
            self.assertEqual(dirs,[src/'new/header-dir'])
            with self.assertRaises(ValueError):rewrite_includes(['-I',str(base)],src,obj)
            with self.assertRaises(ValueError):rewrite_includes(['-I'],src,obj)

    def test_include_closure_drift_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'config.mk';path.write_text('one')
            env=BuildEnvironment.__new__(BuildEnvironment)
            env.inputs={str(path):digest(path)};env.closure={}
            env.capture_closure=lambda:{}
            path.write_text('two')
            with self.assertRaisesRegex(ValueError,'build input changed'):env.verify()

    def test_explicit_profile_and_objtop_mismatch_rejected(self):
        path,plan=self.plans[0];recorded=plan['build_environment']
        with tempfile.TemporaryDirectory(dir=path.parent) as temporary:
            root=Path(temporary);profile=root/'profile';profile.write_text(Path(recorded['profile']).read_text()+'WITH_FAKE=1\n')
            with self.assertRaisesRegex(ValueError,'differs from selected world'):
                BuildEnvironment(Path(plan['source_root']),Path(recorded['objtop']),profile,Path(plan['make']))
            obj=root/'wrong-obj';obj.mkdir();(obj/'.src_opts').write_bytes(Path(recorded['profile']).read_bytes())
            with self.assertRaisesRegex(ValueError,'identity differs'):
                BuildEnvironment(Path(plan['source_root']),obj,obj/'.src_opts',Path(plan['make']))

    def test_make_rebuilds_shared_helper_after_template_change(self):
        path,plan=self.plans[0];recorded=plan['build_environment']
        with tempfile.TemporaryDirectory(dir=path.parent) as temporary:
            root=Path(temporary);component=root/'component'
            shutil.copytree(recorded['component'],component)
            obj=root/'obj';obj.mkdir()
            env=BuildEnvironment(Path(plan['source_root']),Path(recorded['objtop']),Path(recorded['profile']),Path(plan['make']),component)
            env.query(['md4hl.c'],obj=obj)
            output=obj/'md4hl.c';original=output.read_bytes()
            time.sleep(1.1)
            template=component/'mdXhl.c';template.write_bytes(template.read_bytes()+b'\n/* shared-helper-invalidation */\n')
            env.query(['md4hl.c'],obj=obj)
            self.assertNotEqual(output.read_bytes(),original)
            self.assertIn(b'shared-helper-invalidation',output.read_bytes())

unittest.main(argv=['libmd-plan-test'])
