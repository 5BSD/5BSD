# SPDX-License-Identifier: BSD-2-Clause
"""Explicit SDK roots and compiler identities must never select a hidden fallback."""
from pathlib import Path
import importlib.util
import unittest
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

    def test_nonobject_inputs_rejected(self):
        for plan, settings in [(None,{}),([],{}),({},None),({},[])]:
            with self.subTest(plan=plan,settings=settings), self.assertRaisesRegex(ValueError, 'must be objects'):
                sdk_sources(plan,settings)

    def test_unknown_or_boolean_format_rejected(self):
        for value in [None,True,False,0,3,'2']:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'format 1 or 2'):
                sdk_sources({'format':value,'build_environment':{}},{})


if __name__ == '__main__':unittest.main()
