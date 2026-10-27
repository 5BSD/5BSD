# SPDX-License-Identifier: BSD-2-Clause
"""Emit native C/C++ consumers and Kyua-backed TAP tests against selected libraries."""
import shlex
import json
from pathlib import Path
import re
import shutil
import source_headers
import library_dependencies
import component_labels
import configured_tests
from libmd_environment import digest
from libmd_paths import rewrite_includes


def emit(root, data, config_path, src, groups=None):
    config=json.loads(config_path.read_text())
    if set(config)!={'format','suite','tests'} or type(config['format']) is not int or config['format']!=1 or config['suite'] not in ('native-c','native-cxx','native-tap','native-atf'):
        raise ValueError('native-c, native-cxx, native-tap or native-atf test schema required')
    if not isinstance(config['tests'],list) or not config['tests']:
        raise ValueError('nonempty native C test list required')
    framework=config['suite'] in ('native-tap','native-atf')
    interface='atf' if config['suite']=='native-atf' else 'tap'
    libraries={c['metadata']['LIB'] for c in data['components'] if c['metadata']['LIB']}
    lines=['load("@rules_cc//cc:defs.bzl", "cc_test")'];names=set();runtime_checks=[];inputs={str(config_path):digest(config_path),str(Path(__file__)):digest(Path(__file__))}
    inputs[str(Path(source_headers.__file__).resolve())]=digest(Path(source_headers.__file__))
    inputs[str(Path(library_dependencies.__file__).resolve())]=digest(Path(library_dependencies.__file__))
    inputs[str(Path(configured_tests.__file__).resolve())]=digest(Path(configured_tests.__file__))
    if framework:
        for name in ['bsd_kyua.bzl', 'bsd_kyua_metadata.bzl']:
            rule=Path(__file__).with_name(name)
            shutil.copyfile(rule,root/rule.name);inputs[str(rule)]=digest(rule)
        if not (root/'toolchain/bin/extra_kyua').is_file():raise ValueError('Kyua tests require explicitly staged additional tool kyua')
        lines += ['load("@rules_cc//cc:defs.bzl", "cc_binary")', 'load(":bsd_kyua.bzl", "bsd_kyua_test")']
    for test in config['tests']:
        required={'name','dependencies','cflags'}
        if not required<=set(test) or set(test)-required-{'source','sources','args','linkopts','linkage'}:raise ValueError('unexpected native C test fields')
        if ('source' in test)==('sources' in test):raise ValueError('exactly one source or sources field required')
        source_names=[test['source']] if 'source' in test else test['sources']
        if not isinstance(source_names,list) or not source_names or any(not isinstance(v,str) for v in source_names) or len(set(source_names))!=len(source_names):
            raise ValueError('nonempty unique C source list required')
        linkopts=test.get('linkopts',[])
        if not isinstance(linkopts,list) or any(not isinstance(v,str) for v in linkopts):raise ValueError('linkopts must be a string list')
        arguments=test.get('args',[])
        if not isinstance(arguments,list) or any(not isinstance(v,str) for v in arguments):raise ValueError('test args must be a string list')
        if framework and arguments:raise ValueError('framework test arguments require explicit Kyua support')
        name=test['name']
        if not isinstance(name,str) or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',name) or name in names:
            raise ValueError('unique native C test name required')
        names.add(name)
        sources=[]
        for value in source_names:
            relative=Path(value)
            if relative.is_absolute() or '..' in relative.parts or relative.suffix not in (('.cc','.cpp','.cxx','.C') if config['suite']=='native-cxx' else ('.c',)):raise ValueError('source-relative test matching the configured language required')
            source=(src/relative).resolve(strict=True)
            if not source.is_relative_to(src):raise ValueError('test source escapes source tree')
            sources.append(source)
        linkage=test.get('linkage','static')
        if linkage not in ('static','dynamic','static-in-shared'):raise ValueError('unsupported native test linkage')
        if linkage=='static-in-shared' and (config['suite']!='native-c' or arguments):
            raise ValueError('static-in-shared tests require native-c and a no-argument BSD_TEST_ENTRY')
        if framework and linkage=='dynamic':raise ValueError('dynamic framework tests require runner-aware runtime qualification')
        deps=test['dependencies'];flags=test['cflags']
        if not isinstance(deps,list) or not deps or any(d not in libraries for d in deps) or len(deps)!=len(set(deps)):
            raise ValueError('explicit unique selected library dependencies required')
        selections=library_dependencies.program_runtime_selections(deps,data['components'])
        component_index=library_dependencies.component_index(data['components'])
        by_name={entry['library']:library_dependencies.selection_component(entry,component_index)
                 for entry in selections}
        if not isinstance(flags,list) or any(not isinstance(f,str) for f in flags):raise ValueError('C flags must be strings')
        copts,includes=rewrite_includes(flags,src,Path(data['build_environment']['objtop']))
        def snapshot(source):
            if not source.resolve(strict=True).is_relative_to(src):raise ValueError('test input escapes source tree')
            inputs[str(source)]=digest(source)
            target=root/'sources'/source.relative_to(src)
            target.parent.mkdir(parents=True,exist_ok=True)
            if target.exists() and digest(target)!=inputs[str(source)]:raise ValueError('test input conflicts with library snapshot')
            if not target.exists():shutil.copyfile(source,target)
            if digest(target)!=inputs[str(source)]:raise ValueError('test input changed during copy')
            return str(target.relative_to(root))
        # Explicit source include roots supply declared compiler inputs, including
        # test-only private headers. Never read object directories as header roots.
        headers=sorted({snapshot(header) for directory in includes for header in source_headers.collect(directory) if header.is_file()})
        labels=[snapshot(source) for source in sources]
        if linkage=='dynamic':
            selected={name:component['metadata'] for name,component in by_name.items()}
            if any(not selected[d]['SHLIB_NAME'] or selected[d]['SHLIB_NAME'] not in shlex.split(selected[d]['_LIBS']) for d in deps):
                raise ValueError('dynamic test requires configured shared library outputs')
        if linkage in ('dynamic','static-in-shared'):
            resolved=configured_tests.runtime_libraries_from_selections(
                selections,data['components'],groups)
            runtime_libraries={soname:record['artifact'] for soname,record in resolved.items()}
            if linkage=='static-in-shared':
                if any(by_name[d]['metadata']['SHLIB_NAME'] in shlex.split(by_name[d]['metadata']['_LIBS']) for d in deps):
                    raise ValueError('static-in-shared tests require static-only direct dependencies')
                wrapper='lib'+name+'_wrapper.so.1'
                runtime_libraries[wrapper]=wrapper
            runtime_checks.append(dict(name=name,binary=name,libraries=runtime_libraries,args=arguments))
        if linkage=='static-in-shared':
            # A test fixture, not an additional base-system component. The test
            # source implements int BSD_TEST_ENTRY(void); the consumer calls it.
            load='load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")'
            if load not in lines:lines.insert(0,load)
            wrapper_attrs=dict(name=wrapper,srcs=labels+headers,
                deps=library_dependencies.shared_link_labels(deps,data['components']),
                copts=copts+['-DBSD_TEST_ENTRY=bsd_test_entry'],
                linkopts=linkopts+['-Wl,-soname,'+wrapper,'-Wl,-z,defs'],linkshared=True,linkstatic=True)
            lines.append('cc_binary('+', '.join(k+'='+repr(v) for k,v in wrapper_attrs.items())+')')
            lines.append('cc_import(name='+repr(name+'_wrapper')+', shared_library='+repr(':'+wrapper)+')')
            labels=[snapshot(Path(__file__).with_name('tests')/'shared_wrapper_main.c')]
            test_deps=[':'+name+'_wrapper'];copts=[];headers=[];linkopts=[]
        else:
            test_deps=[component_labels.label(by_name[d],d+('_dynamic' if linkage=='dynamic' else '')) for d in deps]
        attrs=dict(name=name,srcs=labels,deps=test_deps,copts=copts,
                   additional_compiler_inputs=headers,linkopts=linkopts,
                   linkstatic=linkage=='static',features=['fully_static_link'] if linkage=='static' else ['bsd_test_runtime_paths'],size='small',args=arguments)
        if framework:
            attrs.pop('size');attrs.pop('args');attrs['name']=name+'_program'
            lines.append('cc_binary('+', '.join(k+'='+repr(v) for k,v in attrs.items())+')')
            test_attrs=dict(name=name,interface=interface,program=':'+name+'_program',kyua='//toolchain:extra_kyua',runtime=['//toolchain:extra_kyua_runtime'],size='small')
            lines.append('bsd_kyua_test('+', '.join(k+'='+repr(v) for k,v in test_attrs.items())+')')
        else:
            lines.append('cc_test('+', '.join(k+'='+repr(v) for k,v in attrs.items())+')')
    for p,h in inputs.items():
        if digest(Path(p))!=h:raise ValueError('native test input changed')
    (root/'native-c-test-inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
    (root/'native-test-inventory.json').write_text(json.dumps({'labels':['//:'+n for n in sorted(names)],'runtime_checks':runtime_checks},indent=2)+'\n')
    return lines
