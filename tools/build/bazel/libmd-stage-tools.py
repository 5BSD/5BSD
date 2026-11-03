#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Materialize explicit userland target and native execution SDK inputs.

This does not replace the execution OS: dynamic interpreters and loaded libraries
must match the recorded host dependencies before running actions. No hermeticity
or Bazel resolution result is implied by successful staging.
"""
import argparse, hashlib, json, os, re, shutil, subprocess
from pathlib import Path
import python_runtime
import userland_sdk


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def runtime_groups(tool_dependencies):
    """Declare each tool's inspected runtime without adding unrelated libraries."""
    return ['filegroup(name=%s, srcs=%s)' %
            (json.dumps(name + '_runtime'), json.dumps([
                'execution-runtime/' + path.lstrip('/') for path in sorted(paths)]))
            for name, paths in sorted(tool_dependencies.items())]


def action_input_groups():
    return [
        'filegroup(name="compile_inputs", srcs=["bin/clang", ":clang_runtime"]+glob(["sysroot/usr/include/**", "sysroot/usr/lib/clang/**"]))',
        'filegroup(name="link_inputs", srcs=["bin/clang", "bin/ld.lld", ":clang_runtime", ":ld.lld_runtime"]+glob(["sysroot/usr/lib/**", "sysroot/lib/**"]))',
        'filegroup(name="archive_inputs", srcs=["bin/llvm-ar", ":llvm-ar_runtime"])',
        'filegroup(name="objcopy_inputs", srcs=["bin/llvm-objcopy", ":llvm-objcopy_runtime"])',
        'filegroup(name="strip_inputs", srcs=["bin/llvm-strip", ":llvm-strip_runtime"])',
    ]


def inspect_execution_dependencies(origins, inspectors):
    dependencies={}; tool_dependencies={}; commands=[]
    for name,path in origins.items():
        tool_dependencies[name]={}
        for flag in ('ldd','readelf'):
            argv=[inspectors[flag]]+([str(path)] if flag=='ldd' else ['-l',str(path)])
            result=subprocess.run(argv,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            commands.append({'command':argv,'status':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
            if result.returncode and not (flag=='ldd' and 'not a dynamic ELF executable' in result.stderr+result.stdout):
                raise ValueError('execution dependency inspection failed: '+name)
            if flag=='ldd':
                for line in result.stdout.splitlines():
                    if '=> not found' in line:raise ValueError('unresolved execution dependency')
                    if '=> /' in line:
                        dep=Path(line.split('=> ',1)[1].split()[0]).resolve(strict=True)
                        dependencies[str(dep)]=digest(dep)
                        tool_dependencies[name][str(dep)]=dependencies[str(dep)]
            else:
                for line in result.stdout.splitlines():
                    if 'Requesting program interpreter:' in line:
                        dep=Path(line.split('Requesting program interpreter:',1)[1].strip().rstrip(']')).resolve(strict=True)
                        dependencies[str(dep)]=digest(dep)
                        tool_dependencies[name][str(dep)]=dependencies[str(dep)]
    return dependencies, tool_dependencies, commands


def materialize(plan_path, tools_path, execution_workspace=None, execution_receipt=None):
    plan_path=plan_path.resolve(strict=True); tools_path=tools_path.resolve(strict=True)
    root=plan_path.parent/'workspace'
    if not plan_path.is_relative_to('/usr/obj') or root.is_symlink() or not root.is_dir():
        raise ValueError('plan and nonsymlink workspace must be below /usr/obj')
    implementation=Path(__file__).resolve(strict=True)
    toolchain_config=implementation.with_name('native_cc_toolchain_config.bzl')
    plan=json.loads(plan_path.read_text()); settings=json.loads(tools_path.read_text())
    environment=plan['build_environment']; obj=Path(environment['objtop']); sdk=obj/'tmp'
    selected_arch = userland_sdk.target_architecture(environment['target'])
    identity = userland_sdk.architecture(selected_arch)
    userland_sdk.verify_profile(environment['profile_assignments'], selected_arch)
    host = None
    if selected_arch == 'amd64':
        if execution_workspace is not None or execution_receipt is not None:
            raise ValueError('native SDK does not accept a separate execution SDK')
    else:
        if execution_workspace is None or execution_receipt is None:
            raise ValueError('cross SDK requires an explicit native execution SDK and receipt')
        execution_workspace = execution_workspace.resolve(strict=True)
        execution_receipt = execution_receipt.resolve(strict=True)
        host = json.loads(execution_receipt.read_text())
        userland_sdk.receipt_architecture(host, 'amd64')
        userland_sdk.verify_snapshot(execution_workspace, host)
        if host.get('format') != 1:
            raise ValueError('execution SDK must be an independent native snapshot')
    required={'execution_tools','objdump','stdout_redirect_source','readelf','ldd'}
    if not required<=set(settings) or set(settings)-required-{'additional_execution_tools','python_stdlib'}:
        raise ValueError('unexpected tool configuration keys')
    if set(settings['execution_tools']) != {'sh','sed','cat','mv','rm','awk'}:
        raise ValueError('explicit generator executable set required')
    origins={name:Path(value).resolve(strict=True) for name,value in settings['execution_tools'].items()}
    origins.update({name:(sdk/'usr/bin'/name).resolve(strict=True) for name in ('clang','cpp','ld.lld','llvm-ar','llvm-nm','llvm-objcopy','llvm-strip')})
    origins['llvm-objdump']=Path(settings['objdump']).resolve(strict=True)
    additional=settings.get('additional_execution_tools',{})
    if not isinstance(additional,dict) or any(not re.fullmatch('[A-Za-z][A-Za-z0-9_]*',name) for name in additional):
        raise ValueError('additional execution tools require simple unique names')
    for name,value in additional.items():
        if not isinstance(value,str) or not Path(value).is_absolute():raise ValueError('absolute additional tool path required')
        origins['extra_'+name]=Path(value).resolve(strict=True)
    python_files={}; python_extensions={}; python_info=None
    if 'python_stdlib' in settings:
        if 'extra_python' not in origins or not Path(settings['python_stdlib']).is_absolute():
            raise ValueError('python_stdlib requires an explicit additional python tool and absolute path')
        python_files,python_extensions,python_info=python_runtime.inventory(origins['extra_python'],settings['python_stdlib'])
    inputs={str(path):digest(path) for path in [*origins.values(),*python_files.values()]}
    inputs[str(Path(python_runtime.__file__).resolve())]=digest(Path(python_runtime.__file__))
    inputs.update(environment['input_sha256'])
    inputs.update({plan['source_origins'][k]:v for k,v in plan['source_sha256'].items()})
    for directory in ('usr/include','usr/lib','lib'):
        for current,dirs,files in os.walk(sdk/directory,followlinks=True):
            for name in files:
                path=Path(current)/name
                if path.is_file():inputs[str(path)]=digest(path)
    for value in ('stdout_redirect_source','readelf','ldd'):
        path=Path(settings[value]).resolve(strict=True);inputs[str(path)]=digest(path)
    inputs[str(plan_path)]=digest(plan_path);inputs[str(tools_path)]=digest(tools_path)
    inputs[str(implementation)]=digest(implementation)
    inputs[str(Path(userland_sdk.__file__).resolve())]=digest(Path(userland_sdk.__file__))
    if host is not None:
        for name, value in {**host['inputs'], **host['execution_host_dependencies'], str(execution_receipt):digest(execution_receipt)}.items():
            if name in inputs and inputs[name] != value:
                raise ValueError('target and execution SDK inputs conflict: '+name)
            inputs[name] = value
    inputs[str(toolchain_config)]=digest(toolchain_config)
    validator=implementation.with_name('static_archive_check.py')
    if python_info:inputs[str(validator)]=digest(validator)
    for path,expected in inputs.items():
        if digest(Path(path)) != expected:raise ValueError('input changed before staging: '+path)
    tc=root/'toolchain'
    if tc.exists():raise ValueError('toolchain destination already exists')
    # Record actual dynamic dependencies. Staging their bytes makes them declared
    # inputs but does not redirect ELF PT_INTERP or the execution host loader.
    dependencies, tool_dependencies, commands = inspect_execution_dependencies({**origins, **python_extensions}, settings)
    tc.mkdir();(tc/'bin').mkdir()
    for directory in ('usr/include','usr/lib','lib'):
        shutil.copytree(sdk/directory,tc/'sysroot'/directory,symlinks=directory!='usr/include')
    for path in (tc/'sysroot').rglob('*'):
        if path.is_symlink() and not path.resolve(strict=True).is_relative_to(tc/'sysroot'):
            raise ValueError('SDK symlink escapes snapshot: '+str(path))
    for name,path in origins.items():shutil.copy2(path,tc/'bin'/name)
    for relative,path in python_files.items():
        target=tc/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
    if python_info:
        (tc/'python-home/runtime.json').write_text(json.dumps({'version':python_info['version']},indent=2)+'\n')
    for path in dependencies:
        destination=tc/'execution-runtime'/path.lstrip('/');destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,destination);destination.chmod(Path(path).stat().st_mode & 0o777)
    shutil.copy2(settings['stdout_redirect_source'],tc/'stdout_redirect.c')
    shutil.copy2(toolchain_config,tc/'cc_toolchain_config.bzl')
    if python_info:
        shutil.copyfile(validator,tc/'bin/static_archive_check.py')
        # The selected static shell remains an explicitly recorded execution-host
        # binding, like ELF interpreters. All action data uses repository paths.
        shell=str(origins['sh'])
        if any(c.isspace() for c in shell):raise ValueError('validator shell path contains whitespace')
        wrapper=tc/'bin/validate_static_library'
        wrapper.write_text('#!'+shell+'\nset -eu\n'
            'validator_bin=${0%/*}\n'
            'unset PYTHONPATH PYTHONSTARTUP\n'
            'PYTHONHOME="$validator_bin/../python-home"\n'
            'export PYTHONHOME\n'
            'exec "$validator_bin/extra_python" -s -P "$validator_bin/static_archive_check.py" '
            '--nm "$validator_bin/llvm-nm" "$@"\n')
        wrapper.chmod(0o755)
    version=Path(environment['compiler_resource']).name;target=environment['target']
    (tc/'identity.bzl').write_text('BSD_TARGET = '+json.dumps(target)+'\n')
    lines=['load("@rules_cc//cc:defs.bzl", "cc_binary")',
           'load("@rules_cc//cc/toolchains:cc_toolchain.bzl", "cc_toolchain")',
           'load(":cc_toolchain_config.bzl", "bsd_cc_config")',
           'package(default_visibility=["//visibility:public"])',
           'exports_files(glob(["bin/*"]))',
           'constraint_setting(name="sdk_identity")',
           'constraint_value(name="selected_sdk", constraint_setting=":sdk_identity")',
           'platform(name="native", constraint_values=["@platforms//os:freebsd", "@platforms//cpu:x86_64", ":selected_sdk"])',
           'filegroup(name="inputs", srcs=glob(["bin/**", "sysroot/**", "execution-runtime/**", "python-home/**"]))',
           'filegroup(name="empty")',
           'bsd_cc_config(name="config", target=%s, cpu="k8", clang_version=%s, archive_validation=%s)'%(json.dumps(target),json.dumps(version),str(bool(python_info))),
           'cc_toolchain(name="compiler", toolchain_identifier="bsd-staged-clang", toolchain_config=":config", all_files=":inputs", compiler_files=":compile_inputs", as_files=":compile_inputs", linker_files=":link_inputs", ar_files=":archive_inputs", objcopy_files=":objcopy_inputs", strip_files=":strip_inputs", dwp_files=":empty", supports_param_files=1)',
           'toolchain(name="registered", toolchain=":compiler", toolchain_type="@bazel_tools//tools/cpp:toolchain_type", exec_compatible_with=["@platforms//os:freebsd", "@platforms//cpu:x86_64", ":selected_sdk"], target_compatible_with=["@platforms//os:freebsd", "@platforms//cpu:x86_64", ":selected_sdk"])',
           'cc_binary(name="stdout_redirect", srcs=["stdout_redirect.c"], linkstatic=True, features=["fully_static_link"])']
    lines += runtime_groups(tool_dependencies) + action_input_groups()
    lines += ['alias(name=%s, actual=%s)'%(json.dumps(name),json.dumps('bin/'+name)) for name in [*settings['execution_tools'],*['extra_'+n for n in additional]]]
    if python_info:
        runtime_labels=[':extra_python_runtime']+[':'+name+'_runtime' for name in python_extensions]
        lines.append('filegroup(name="python_stdlib", srcs=glob(["python-home/**"])+%s)' % json.dumps(runtime_labels))
    if host is not None:
        # Execution and target platforms share one SDK identity while selecting
        # distinct ABI toolchains. Source-built cfg=exec tools use this host.
        native_constraint = '"@platforms//cpu:x86_64"'
        target_constraint = json.dumps('@platforms//cpu:' + identity['platform_cpu'])
        for i, line in enumerate(lines):
            if line.startswith('bsd_cc_config('):
                lines[i] = line.replace('cpu="k8"', 'cpu=' + json.dumps(identity['toolchain_cpu']))
            elif line.startswith('toolchain(name="registered"'):
                before, sep, after = line.partition('target_compatible_with=')
                lines[i] = before + sep + after.replace(native_constraint, target_constraint)
        lines.append('platform(name=%s, constraint_values=["@platforms//os:freebsd", %s, ":selected_sdk"])' % (json.dumps(selected_arch), target_constraint))
        host_tc = tc/'host'
        shutil.copytree(execution_workspace/'toolchain', host_tc, symlinks=True)
        for name, expected in host['snapshot'].items():
            relative = Path(name).relative_to('toolchain')
            if digest(host_tc/relative) != expected:
                raise ValueError('execution SDK copy changed: '+name)
        # Host BUILD is generated from explicit receipt identities, never edited
        # by opaque replacement of the source or compiler binaries.
        host_lines = [
            'load("@rules_cc//cc/toolchains:cc_toolchain.bzl", "cc_toolchain")',
            'load(":cc_toolchain_config.bzl", "bsd_cc_config")',
            'package(default_visibility=["//visibility:public"])',
            'filegroup(name="inputs", srcs=glob(["bin/**", "sysroot/**", "execution-runtime/**", "python-home/**"]))',
            'filegroup(name="empty")',
            'bsd_cc_config(name="config", target=%s, cpu="k8", clang_version=%s, archive_validation=%s)' %
                (json.dumps(host['target']), json.dumps(host['compiler_resource_version']), str(bool(host['python_runtime']))),
            'cc_toolchain(name="compiler", toolchain_identifier="bsd-staged-clang", toolchain_config=":config", all_files=":inputs", compiler_files=":compile_inputs", as_files=":compile_inputs", linker_files=":link_inputs", ar_files=":archive_inputs", objcopy_files=":objcopy_inputs", strip_files=":strip_inputs", dwp_files=":empty", supports_param_files=1)',
            'toolchain(name="registered", toolchain=":compiler", toolchain_type="@bazel_tools//tools/cpp:toolchain_type", exec_compatible_with=["@platforms//os:freebsd", "@platforms//cpu:x86_64", "//toolchain:selected_sdk"], target_compatible_with=["@platforms//os:freebsd", "@platforms//cpu:x86_64", "//toolchain:selected_sdk"])',
        ]
        host_lines += runtime_groups(host['tool_execution_dependencies']) + action_input_groups()
        (host_tc/'BUILD.bazel').write_text('\n'.join(host_lines)+'\n')
        userland_sdk.verify_snapshot(execution_workspace, host)
    (tc/'BUILD.bazel').write_text('\n'.join(lines)+'\n')
    for path,expected in inputs.items():
        if digest(Path(path))!=expected:raise ValueError('input changed during staging: '+path)
    for path,expected in dependencies.items():
        if digest(Path(path))!=expected:raise ValueError('execution runtime changed: '+path)
    if python_info:
        current,_,_=python_runtime.inventory(origins['extra_python'],settings['python_stdlib'])
        if current!=python_files:raise ValueError('Python standard-library inventory changed during staging')
    snapshot={str(path.relative_to(root)):digest(path) for path in tc.rglob('*') if path.is_file()}
    result={'format':1,'scope':'native amd64 candidate SDK snapshot; no Bazel execution or hermeticity claim','inputs':inputs,'execution_host_dependencies':dependencies,'tool_execution_dependencies':tool_dependencies,'dependency_commands':commands,'tool_origins':{k:str(v) for k,v in origins.items()},'snapshot':snapshot,'python_runtime':python_info,'bazel_analyzed':False,'bazel_built':False,'target':target}
    result['compiler_resource_version'] = version
    if host is not None:
        result.update(format=2, scope='explicit target SDK plus independently bound native execution SDK; no world/runtime qualification',
                      execution_target=host['target'], execution_sdk={
                          'workspace':str(execution_workspace), 'receipt':str(execution_receipt),
                          'receipt_sha256':digest(execution_receipt),
                          'snapshot_sha256':userland_sdk.snapshot_digest(host)})
        userland_sdk.receipt_architecture(result, selected_arch)
    (plan_path.parent/'toolchain-inputs.json').write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--plan',type=Path,required=True);parser.add_argument('--tools',type=Path,required=True)
    parser.add_argument('--execution-workspace',type=Path);parser.add_argument('--execution-receipt',type=Path)
    args=parser.parse_args();materialize(args.plan,args.tools,args.execution_workspace,args.execution_receipt)
