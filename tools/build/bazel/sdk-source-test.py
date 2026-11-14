# SPDX-License-Identifier: BSD-2-Clause
"""Explicit SDK roots and compiler identities must never select a hidden fallback."""
from pathlib import Path
import importlib.util
import unittest
import shutil
import tempfile
from unittest import mock
from userland_sdk import sdk_sources, COMPILER_TOOLS


class SdkSources(unittest.TestCase):
    def explicit(self):
        return ({'format': 2, 'build_environment': {'sdk_root': '/usr/obj/native-sdk/root'}},
                {'compiler_tools': {name: '/usr/obj/native-sdk/tools/'+name for name in COMPILER_TOOLS}})

    def test_existing_make_adapter(self):
        root, compilers, kind = sdk_sources({'format':1, 'build_environment':{'objtop':'/usr/obj/usr/src/amd64.amd64'}}, {})
        self.assertEqual(root, Path('/usr/obj/usr/src/amd64.amd64/tmp'))
        self.assertEqual(kind, 'make-object-root')
        self.assertEqual(compilers['clang'], root/'usr/bin/clang')

    def test_explicit_root_has_no_make_requirement(self):
        plan, settings = self.explicit()
        root, compilers, kind = sdk_sources(plan, settings)
        self.assertEqual(root, Path('/usr/obj/native-sdk/root'))
        self.assertEqual(kind, 'explicit-sdk-root')
        self.assertEqual({str(v) for v in compilers.values()}, set(settings['compiler_tools'].values()))

    def test_compilers_can_be_separate_from_target_root(self):
        plan, settings = self.explicit()
        settings['compiler_tools'] = {name:'/opt/host-compiler/bin/'+name for name in COMPILER_TOOLS}
        root, compilers, kind = sdk_sources(plan, settings)
        self.assertEqual(compilers['clang'], Path('/opt/host-compiler/bin/clang'))
        self.assertEqual(root, Path('/usr/obj/native-sdk/root'))

    def test_missing_explicit_compiler_rejected(self):
        for name in COMPILER_TOOLS:
            plan, settings = self.explicit(); del settings['compiler_tools'][name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'complete explicit compiler'):
                sdk_sources(plan, settings)

    def test_unknown_compiler_rejected(self):
        plan, settings = self.explicit(); settings['compiler_tools']['surprise']='/bin/true'
        with self.assertRaisesRegex(ValueError, 'complete explicit compiler'):
            sdk_sources(plan, settings)

    def test_root_selection_cannot_be_ambiguous(self):
        plan, settings = self.explicit(); plan['build_environment']['objtop']='/usr/obj/old'
        with self.assertRaisesRegex(ValueError, 'must not also select'):
            sdk_sources(plan, settings)

    def test_old_adapter_rejects_explicit_overrides(self):
        plan={'format':1,'build_environment':{'objtop':'/usr/obj/old','sdk_root':'/usr/obj/new'}}
        with self.assertRaisesRegex(ValueError, 'require plan format 2'):sdk_sources(plan,{})
        del plan['build_environment']['sdk_root']
        with self.assertRaisesRegex(ValueError, 'require plan format 2'):sdk_sources(plan,{'compiler_tools':{}})

    def test_noncanonical_or_wrong_root_rejected(self):
        for value in ['relative','/home/koryheard/sdk','/usr/obj','/usr/obj/a/../b','/usr/obj//a','/usr/obj/a/','/usr/obj/a\n']:
            plan, settings=self.explicit();plan['build_environment']['sdk_root']=value
            with self.subTest(value=value), self.assertRaises(ValueError):sdk_sources(plan,settings)

    def test_missing_explicit_root_rejected(self):
        plan, settings=self.explicit();del plan['build_environment']['sdk_root']
        with self.assertRaisesRegex(ValueError, 'absolute SDK root'):sdk_sources(plan,settings)

    def test_invalid_compiler_path_rejected(self):
        for value in ['clang','/usr/obj/a/../clang','/usr/obj//clang',42,None]:
            plan, settings=self.explicit();settings['compiler_tools']['clang']=value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'absolute compiler tool'):
                sdk_sources(plan,settings)

    def test_generated_toolchain_count_is_not_a_fixed_receipt_value(self):
        spec=importlib.util.spec_from_file_location('sdk_stage', Path(__file__).with_name('libmd-stage-tools.py'))
        stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
        lines,metadata=stage.freestanding_toolchains('x86_64-unknown-freebsd16.0','21')
        count=metadata['freestanding_toolchain_count']
        self.assertEqual(metadata['freestanding_toolchains'],2)
        declarations=[line for line in lines if line.startswith('toolchain(')]
        self.assertEqual(count,len(declarations))
        self.assertEqual(count,4)
        for arch in ('amd64','i386','aarch64','riscv64'):
            self.assertTrue(any('standalone_'+arch+'_registered' in line for line in declarations))

    def world(self):
        return {'format':3, 'build_environment':{
            'objtop':'/usr/obj/world', 'compiler_mode':'system',
            'compiler_executable':'/opt/llvm/bin/clang',
            'compiler_selected':'/usr/obj/world/tmp/legacy/bin/cc',
            'compiler_resource':'/opt/llvm/lib/clang/21',
            'sdk_compiler_resource':'/usr/obj/world/tmp/usr/lib/clang/21',
            'compiler_tools':{name:'/opt/llvm/bin/'+name for name in COMPILER_TOOLS}}}

    def test_world_selected_compiler_is_separate_from_sdk(self):
        root, compilers, kind = sdk_sources(self.world(), {})
        self.assertEqual(root, Path('/usr/obj/world/tmp'))
        self.assertEqual(compilers['clang'], Path('/opt/llvm/bin/clang'))
        self.assertEqual(kind, 'make-world-selected-tools')

    def test_world_tools_cannot_fall_back_or_be_overridden(self):
        for name in COMPILER_TOOLS:
            plan=self.world(); del plan['build_environment']['compiler_tools'][name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'complete world compiler'):
                sdk_sources(plan,{})
        with self.assertRaisesRegex(ValueError, 'must not override'):
            sdk_sources(self.world(), {'compiler_tools':{}})
        plan=self.world();plan['build_environment']['compiler_tools']['clang']='/opt/other/clang'
        with self.assertRaisesRegex(ValueError, 'differs from selected compiler'):
            sdk_sources(plan,{})

    def test_world_identity_fields_cannot_be_omitted(self):
        for field in ['compiler_selected','compiler_executable','compiler_mode','compiler_resource','sdk_compiler_resource','compiler_tools']:
            plan=self.world(); del plan['build_environment'][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                sdk_sources(plan,{})
        plan=self.world();plan['build_environment']['compiler_resource']='/'
        with self.assertRaisesRegex(ValueError, 'versioned world compiler resource'):
            sdk_sources(plan,{})

    def test_world_resources_and_mode_must_match(self):
        plan=self.world();plan['build_environment']['sdk_compiler_resource']='/usr/obj/world/tmp/usr/lib/clang/20'
        with self.assertRaisesRegex(ValueError, 'declared version'):
            sdk_sources(plan,{})
        plan=self.world();plan['build_environment']['compiler_mode']='auto'
        with self.assertRaisesRegex(ValueError, 'explicit world compiler mode'):
            sdk_sources(plan,{})
        plan=self.world();plan['format']=1
        with self.assertRaisesRegex(ValueError, 'requires world-selected'):
            sdk_sources(plan,{})

    def test_preparer_never_replaces_a_conflicting_input_hash(self):
        path=Path(__file__).with_name('libmd-stage-tools.py')
        spec=importlib.util.spec_from_file_location('stage_binding_test',path)
        stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
        original={'/input/compiler':'a'*64}
        stage.bind_inputs(original, {'/input/compiler':'a'*64})
        with self.assertRaisesRegex(ValueError, 'conflicting SDK input binding'):
            stage.bind_inputs(original, {'/input/new':'c'*64, '/input/compiler':'b'*64})
        self.assertEqual(original, {'/input/compiler':'a'*64})

    def test_nonobject_inputs_rejected(self):
        for plan, settings in [(None,{}),([],{}),({},None),({},[])]:
            with self.subTest(plan=plan,settings=settings), self.assertRaisesRegex(ValueError, 'must be objects'):
                sdk_sources(plan,settings)

    def test_unknown_or_boolean_format_rejected(self):
        for value in [None,True,False,0,4,'2']:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'format 1, 2 or 3'):
                sdk_sources({'format':value,'build_environment':{}},{})


class SdkCopyBindings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).with_name('libmd-stage-tools.py')
        spec=importlib.util.spec_from_file_location('sdk_copy_bindings_test',path)
        cls.stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.stage)

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.source=self.root/'source';self.source.mkdir();self.dest=self.root/'snapshot';self.dest.mkdir();self.file=self.source/'file';self.file.write_bytes(b'expected');self.bindings={str(self.file):self.stage.digest(self.file)}
    def verify(self):self.stage.verify_bound_tree(self.source,self.dest,self.bindings,snapshot_root=self.dest)
    def test_copied_file(self):
        self.stage.copy_bound_file(self.file,self.dest/'file',self.bindings);self.verify()
    def snapshot(self):
        return {str(path.relative_to(self.dest)): self.stage.digest(path)
                for path in self.dest.rglob('*') if path.is_file()}

    def test_copy_metadata_and_final_receipt_binding(self):
        self.file.chmod(0o755)
        bindings=self.stage.copy_bound_file(self.file,self.dest/'file',self.bindings,metadata=True)
        self.assertEqual((self.dest/'file').stat().st_mode & 0o777,0o755)
        self.stage.verify_bound_payload(bindings,self.dest,self.snapshot())
        (self.dest/'file').write_bytes(b'changed after copy')
        with self.assertRaisesRegex(ValueError,'changed before receipt'):
            self.stage.verify_bound_payload(bindings,self.dest,self.snapshot())
    def test_tree_receipt_binding_rechecks_every_file(self):
        shutil.copytree(self.source,self.dest,dirs_exist_ok=True)
        bindings=self.stage.verify_bound_tree(self.source,self.dest,self.bindings,snapshot_root=self.dest)
        self.assertEqual(bindings[str(self.dest/'file')]['source'],str(self.file))
        self.stage.verify_bound_payload(bindings,self.dest,self.snapshot())
        (self.dest/'file').write_bytes(b'changed after tree copy')
        with self.assertRaisesRegex(ValueError,'changed before receipt'):
            self.stage.verify_bound_payload(bindings,self.dest,self.snapshot())
    def test_unbound_file(self):
        with self.assertRaisesRegex(ValueError,'no input binding'):self.stage.copy_bound_file(self.file,self.dest/'file',{})
        self.assertFalse((self.dest/'file').exists())
    def test_transient_source_mutation_with_restoration(self):
        original=shutil.copyfile
        def torn(source,dest):
            old=source.read_bytes();source.write_bytes(b'transient');original(source,dest);source.write_bytes(old)
        with mock.patch.object(self.stage.shutil,'copyfile',side_effect=torn):
            with self.assertRaisesRegex(ValueError,'copied payload differs'):self.stage.copy_bound_file(self.file,self.dest/'file',self.bindings)
        self.assertEqual(self.stage.digest(self.file),self.bindings[str(self.file)])
    def test_changed_tree_payload(self):
        (self.dest/'file').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'differs from input inventory'):self.verify()
    def test_added_and_missing_inventory(self):
        for missing in [True,False]:
            with self.subTest(missing=missing):
                if not missing:(self.dest/'file').write_bytes(b'expected');(self.dest/'extra').write_bytes(b'extra')
                with self.assertRaisesRegex(ValueError,'differs from input inventory'):self.verify()
    def test_final_snapshot_resolves_directory_alias(self):
        other=self.source/'other';other.mkdir()
        (other/'library').write_bytes(b'library')
        (self.source/'alias').symlink_to('other',target_is_directory=True)
        for name in ['other/library','alias/library']:
            self.bindings[str(self.source/name)]=self.stage.digest(self.source/name)
        shutil.copytree(self.source,self.dest,dirs_exist_ok=True,symlinks=True)
        bindings=self.stage.verify_bound_tree(self.source,self.dest,self.bindings,snapshot_root=self.dest)
        snapshot=self.snapshot()
        self.assertNotIn('alias/library',snapshot)
        self.stage.verify_bound_payload(bindings,self.dest,snapshot)

    def test_directory_cycle_is_rejected(self):
        shutil.copytree(self.source,self.dest,dirs_exist_ok=True)
        (self.dest/'cycle').symlink_to('.')
        with self.assertRaisesRegex(ValueError,'directory cycle'):
            self.verify()
    def test_symlink_escape(self):
        (self.dest/'file').symlink_to(self.file)
        with self.assertRaisesRegex(ValueError,'escapes snapshot'):self.verify()
    def test_symlink_between_sysroot_directories(self):
        other=self.source/'other';other.mkdir();(other/'library').write_bytes(b'library');self.bindings[str(other/'library')]=self.stage.digest(other/'library')
        (self.source/'alias').symlink_to('other/library');self.bindings[str(self.source/'alias')]=self.stage.digest(other/'library')
        shutil.copytree(self.source,self.dest,dirs_exist_ok=True,symlinks=True);self.verify()

if __name__ == '__main__':unittest.main()
