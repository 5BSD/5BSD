#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Native declaration checks, not Bazel action analysis or guest qualification."""
import argparse, ast, importlib.util, json, tempfile, unittest
from pathlib import Path


def module(name, filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result

stage=module('stage','libmd-stage-tools.py');emitter=module('emitter','libmd-build.py')
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--toolchain-receipt',type=Path,required=True)
parser.add_argument('--plan',type=Path,required=True)
args=parser.parse_args()

class RuntimeInputs(unittest.TestCase):
    def test_actual_dependency_inspection_and_action_groups(self):
        old=json.loads(args.toolchain_receipt.read_text())
        origins={name:Path(path) for name,path in old['tool_origins'].items()}
        deps,per_tool,commands=stage.inspect_execution_dependencies(origins,{'ldd':'/usr/bin/ldd','readelf':'/usr/bin/readelf'})
        self.assertEqual(deps,old['execution_host_dependencies'])
        self.assertEqual(set(per_tool),set(origins))
        if 'tool_execution_dependencies' in old:
            self.assertEqual(per_tool,old['tool_execution_dependencies'])
        self.assertEqual(per_tool['clang'],{})
        self.assertEqual(per_tool['llvm-ar'],{})
        groups={}
        def filegroup(name,srcs):groups[name]=srcs
        # These declaration statements are also valid Python. Executing them
        # checks list construction/reference resolution; it is not Starlark analysis.
        text='\n'.join(stage.runtime_groups(per_tool)+stage.action_input_groups())
        exec(compile(text,'generated-input-groups','exec'),{'filegroup':filegroup,'glob':lambda patterns:[]})
        def expanded(name):
            result=set()
            for item in groups[name]:
                result.update(expanded(item[1:]) if item.startswith(':') else [item])
            return result
        for path in per_tool['llvm-objdump']:
            runtime='execution-runtime/'+path.lstrip('/')
            self.assertNotIn(runtime,expanded('compile_inputs'))
            self.assertNotIn(runtime,expanded('archive_inputs'))
            self.assertIn(runtime,expanded('llvm-objdump_runtime'))
        for path in per_tool['awk']:self.assertIn('execution-runtime/'+path.lstrip('/'),expanded('awk_runtime'))
        self.assertEqual(expanded('archive_inputs'),{'bin/llvm-ar'})

    def test_emitter_passes_only_named_generator_runtime_groups(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'workspace').mkdir();plan=root/'plan.json';plan.write_bytes(args.plan.read_bytes())
            workspace=emitter.emit(plan);tree=ast.parse((workspace/'BUILD.bazel').read_text())
            calls=[item.value for item in tree.body if isinstance(item,ast.Expr) and isinstance(item.value,ast.Call)]
            generator_calls=[call for call in calls if isinstance(call.func,ast.Name) and call.func.id=='libmd_generated']
            self.assertTrue(generator_calls)
            for call in generator_calls:
                values={kw.arg:kw.value for kw in call.keywords}
                expected={'sh','sed','mv','rm'}
                if ast.literal_eval(values['kind'])=='manual':
                    expected.add('cat')
                    self.assertEqual(ast.literal_eval(values['cat']),'//toolchain:cat')
                else:
                    self.assertNotIn('cat',values)
                self.assertEqual(set(ast.literal_eval(values['execution_runtime'])),{'//toolchain:'+name+'_runtime' for name in expected})
            version=[call for call in calls if isinstance(call.func,ast.Name) and call.func.id=='bsd_version_map']
            self.assertEqual(len(version),1)
            values={kw.arg:kw.value for kw in version[0].keywords}
            self.assertEqual(ast.literal_eval(values['awk_runtime']),'//toolchain:awk_runtime')

    def test_version_action_has_awk_runtime_inputs(self):
        text=Path(__file__).with_name('native_version_map.bzl').read_text()
        tree=ast.parse(text)
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='run']
        self.assertEqual(len(calls),2)
        tools=[kw.value for kw in calls[1].keywords if kw.arg=='tools']
        self.assertEqual(len(tools),1)
        self.assertEqual(ast.unparse(tools[0]),'[ctx.executable.awk] + ctx.files.awk_runtime')
        self.assertIn('"awk_runtime": attr.label(mandatory = True, cfg = "exec")',text)

unittest.main(argv=['libmd-runtime-inputs-test'])
