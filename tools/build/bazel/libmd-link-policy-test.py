#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check maintained archive/link policies in emitted graph; not Bazel analysis."""
import argparse,ast,importlib.util,json,shlex,tempfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('emitter',Path(__file__).with_name('libmd-build.py'))
emitter=importlib.util.module_from_spec(spec);spec.loader.exec_module(emitter)
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--plan',type=Path,required=True);args=parser.parse_args()

class Policy(unittest.TestCase):
    def test_unsupported_archive_changes_rejected_before_emission(self):
        original=json.loads(args.plan.read_text())
        for flags in ('-crsU','-crsDT','-crsD --thin',''):
            with self.subTest(flags=flags),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);(root/'workspace').mkdir();plan=root/'plan.json'
                data=json.loads(json.dumps(original));data['metadata']['ARFLAGS']=flags;plan.write_text(json.dumps(data))
                with self.assertRaisesRegex(ValueError,'unsupported maintained ARFLAGS'):emitter.emit(plan)
                self.assertEqual(list((root/'workspace').iterdir()),[])

    def test_profile_linker_flags_not_forced_by_toolchain(self):
        original=json.loads(args.plan.read_text())
        for enabled in (True,False):
            with self.subTest(enabled=enabled),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);(root/'workspace').mkdir();plan=root/'plan.json';data=json.loads(json.dumps(original))
                flags=[flag for flag in shlex.split(data['metadata']['LDFLAGS']) if flag not in ('-Wl,-znow','-Wl,-zrelro')]
                if enabled:flags+=['-Wl,-znow','-Wl,-zrelro']
                data['metadata']['LDFLAGS']=shlex.join(flags);plan.write_text(json.dumps(data))
                workspace=emitter.emit(plan);tree=ast.parse((workspace/'BUILD.bazel').read_text())
                binaries=[node.value for node in tree.body if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id=='cc_binary']
                self.assertEqual(len(binaries),1)
                options=ast.literal_eval(next(kw.value for kw in binaries[0].keywords if kw.arg=='linkopts'))
                self.assertEqual('-Wl,-znow' in options,enabled);self.assertEqual('-Wl,-zrelro' in options,enabled)
        tree=ast.parse(Path(__file__).with_name('native_cc_toolchain_config.bzl').read_text())
        strings=[node.value for node in ast.walk(tree) if isinstance(node,ast.Constant) and isinstance(node.value,str)]
        self.assertFalse(any('-znow' in s or '-zrelro' in s for s in strings))

unittest.main(argv=['libmd-link-policy-test'])
