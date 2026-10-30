# SPDX-License-Identifier: BSD-2-Clause
"""Register configured native ATF programs with declared runtime library checks."""
import json
from collections import deque
import shutil
from pathlib import Path
import library_dependencies
import component_labels
import library_link_sequence
import configured_test_policy
from libmd_environment import digest


def runtime_libraries(component, components, groups=None, program_runtimes=None):
    selections=(library_dependencies.resolve_selections(component,components) if component['metadata'].get('LIB')
                else library_link_sequence.resolve(component,components))
    return runtime_libraries_from_selections(
        selections +
        library_dependencies.program_runtime_selections(program_runtimes or [],components), components, groups)


def runtime_libraries_from_selections(selections, components, groups=None):
    groups=groups or {}
    selected=library_dependencies.component_index(components)
    pending=deque(selections)
    seen=set();libraries={}
    while pending:
        entry=pending.popleft();name=entry['library'];key=(entry['component'],entry['variant'])
        if key in seen:continue
        seen.add(key);candidate=library_dependencies.selection_component(entry,selected);metadata=candidate['metadata']
        if entry['variant']=='normal' and library_dependencies.shared_link_target(metadata)==name+'_dynamic':
            soname=metadata['SHLIB_NAME']
            if not soname or Path(soname).name!=soname:raise ValueError('invalid runtime SONAME')
            record=dict(component=entry['component'],label=component_labels.label(candidate,name+'_soname'),artifact=component_labels.artifact(candidate,soname))
            if soname in libraries and libraries[soname]!=record:raise ValueError('ambiguous runtime SONAME')
            libraries[soname]=record
        if entry['variant']=='normal' and candidate.get('shared_link_script'):
            if entry['component'] not in groups:
                raise ValueError('runtime GROUP inventory missing: '+name)
            for member in groups[entry['component']]:
                if member['component']==entry['component']:continue
                pending.append(dict(component=member['component'],library=member['library'],
                    variant='normal' if member['kind']=='shared' else member['variant']))
        pending.extend(library_dependencies.resolve_selections(candidate,components))
    return libraries


def suite_modules(component, components):
    """Select shared-only fixtures by their maintained installation directory."""
    directory=component['metadata']['BINDIR']
    if not directory or not Path(directory).is_absolute() or '..' in Path(directory).parts:
        raise ValueError('configured test requires an absolute installation directory')
    result={}
    for candidate in components:
        metadata=candidate['metadata']
        if metadata['LIB'] or metadata['PROG'] or not metadata['SHLIB_NAME']:
            continue
        if metadata['SHLIBDIR']!=directory:
            continue
        name=metadata['SHLIB_NAME']
        if Path(name).name!=name or name in ('.','..') or name in result:
            raise ValueError('ambiguous suite module basename')
        result[name]=candidate
    return result


def emit(root, components, records, groups=None, program_runtimes=None):
    if not records:return {}
    required=('extra_kyua','extra_python')
    if any(not (root/'toolchain/bin'/name).is_file() for name in required):
        raise ValueError('configured ATF tests require staged Kyua and Python tools')
    inputs={str(Path(module).resolve()):digest(Path(module)) for module in (__file__,configured_test_policy.__file__,library_link_sequence.__file__,component_labels.__file__)}
    policies={}
    for name in ('bsd_kyua.bzl','bsd_kyua_metadata.bzl','elf-runtime-check.py','libmd_environment.py'):
        path=Path(__file__).with_name(name);shutil.copyfile(path,root/name);inputs[str(path)]=digest(path)
    packages={}
    inventory_path=root/'native-test-inventory.json'
    inventory=json.loads(inventory_path.read_text()) if inventory_path.exists() else dict(labels=[],runtime_checks=[])
    for component,binary in records:
        name=component['metadata']['PROG']+'_native_atf'
        label=component_labels.label(component,name)
        identity=component_labels.artifact(component,name)
        lines=packages.setdefault(component['component'],['load("//:bsd_kyua.bzl", "bsd_kyua_test")'])
        if label in inventory['labels']:raise ValueError('duplicate configured native test')
        policy=configured_test_policy.translate(component.get('test_policy'))
        policies[identity]=policy
        libraries=runtime_libraries(component,components,groups=groups,program_runtimes=program_runtimes)
        fixture_files={};module_checks=[];module_dependencies={}
        for module_name,module in suite_modules(component,components).items():
            module_label=component_labels.label(module,module_name+'_suite_module')
            if module_name in libraries or module_name in fixture_files:
                raise ValueError('suite module conflicts with runtime library')
            fixture_files[module_name]=module_label
            dependencies=runtime_libraries(module,components,groups=groups,program_runtimes=program_runtimes)
            if not dependencies:raise ValueError('module qualification requires declared runtime libraries')
            module_dependencies[module_name]=sorted(dependencies)
            module_checks.append(dict(name=module_name,
                binary=component_labels.artifact(module,'test/'+module_name),
                libraries={key:record['artifact'] for key,record in dependencies.items()}))
            for soname,record in dependencies.items():
                if soname in libraries:
                    if libraries[soname]!=record:raise ValueError('module runtime dependency conflicts with program')
                    continue
                if soname in fixture_files and fixture_files[soname]!=record['label']:
                    raise ValueError('conflicting suite runtime artifact')
                fixture_files[soname]=record['label']
        attrs=dict(name=name,interface='atf',program=':'+binary,kyua='//toolchain:extra_kyua',
            runtime=['//toolchain:extra_kyua_runtime','//toolchain:python_stdlib','//:libmd_environment.py'],
            python='//toolchain:extra_python',python_home='//toolchain:python-home/runtime.json',runtime_checker='//:elf-runtime-check.py',
            runtime_libraries={v['label']:k for k,v in libraries.items()},suite_files={label:name for name,label in fixture_files.items()},module_dependencies=module_dependencies,clean_environment=True,size='medium',case_timeout=0,test_metadata=json.dumps(policy['metadata']),test_environment=policy['environment'],suite=policy['suite'],tags=policy['tags'])
        lines.append('bsd_kyua_test('+', '.join(k+'='+repr(v) for k,v in attrs.items())+')')
        inventory['labels'].append(label)
        if libraries:
            inventory['runtime_checks'].append(dict(name=identity,binary=component_labels.artifact(component,binary),invocation=component_labels.artifact(component,name+'.suite/'+binary),libraries={k:v['artifact'] for k,v in libraries.items()},args=['-l'],modules=module_checks))
    inventory['labels'].sort()
    for path,expected in inputs.items():
        if digest(Path(path))!=expected:raise ValueError('configured test input changed')
    inventory_path.write_text(json.dumps(inventory,indent=2)+'\n')
    (root/'configured-test-policy.json').write_text(json.dumps(policies,indent=2)+'\n')
    (root/'configured-test-inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
    return packages
