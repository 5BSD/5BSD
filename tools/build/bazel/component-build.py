#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Emit native C/C++ library and C program compilation from selected component metadata.

Installation, generated files and package completeness are separate gates.
"""
import argparse,json,shlex,shutil
from pathlib import Path
from libmd_environment import digest
from libmd_paths import rewrite_includes
import bzip2_tests
import native_c_tests
import library_install
import stage_install
import configured_version_map
import source_headers
import configured_fidl
import library_dependencies
import libmd_paths
import static_sources
import source_compile_flags
import link_group_inventory
import configured_lexyacc
import configured_libmd
import configured_rpc
import configured_nls
import configured_tests
import component_plans
import component_labels
import program_compile
import library_link_sequence
import native_link_options
import shared_modules

def emit(a):
    data=component_plans.load([a.plan,*getattr(a,'additional_plan',[])],a.src)
    program_runtimes=getattr(a,'program_runtime_library',[])
    library_dependencies.program_runtime_selections(program_runtimes,data['components'])
    # Source root is explicit rather than inferred from component depth.
    src=a.src.resolve(strict=True);out=a.output.resolve()
    if out.exists() or not out.is_relative_to('/usr/obj') or out==Path('/usr/obj') or out.is_relative_to(src) or src.is_relative_to(out):raise ValueError('fresh output below /usr/obj required')
    if data['status']!='configured':raise ValueError('configured component inventory required')
    for p,h in data['input_sha256'].items():
        if digest(Path(p))!=h:raise ValueError('component input changed: '+p)
    receipt=json.loads(a.toolchain_receipt.read_text());origin=a.toolchain_workspace.resolve(strict=True)
    if receipt['target']!=data['build_environment']['target']:raise ValueError('SDK target mismatch')
    for p,h in receipt['inputs'].items():
        if digest(Path(p))!=h:raise ValueError('SDK input changed: '+p)
    for p,h in receipt['snapshot'].items():
        if Path(p).is_absolute() or '..' in Path(p).parts or digest(origin/p)!=h:raise ValueError('SDK snapshot changed: '+p)
    out.mkdir(parents=True);shutil.copytree(origin/'toolchain',out/'toolchain',symlinks=True)
    shutil.copyfile(a.module_lock,out/'MODULE.bazel.lock')
    shutil.copyfile(Path(__file__).with_name('native_cc.bzl'),out/'native_cc.bzl')
    shutil.copyfile(Path(__file__).with_name('source_identity.bzl'),out/'source_identity.bzl')
    shutil.copyfile(Path(__file__).with_name('bsd_dtrace.bzl'),out/'bsd_dtrace.bzl')
    shutil.copyfile(Path(__file__).with_name('bsd_fidl.bzl'),out/'bsd_fidl.bzl')
    lines=['load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import", "cc_library")','load("//:native_cc.bzl", "bsd_library", "bsd_shared_alias", "bsd_template", "bsd_static_source", "bsd_source_alias")']
    shutil.copyfile(Path(__file__).with_name('bsd_artifacts.bzl'),out/'bsd_artifacts.bzl')
    lines.append('load("//:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")')
    absent_includes=set()
    configured_test_records=[]
    targets=set();sources={str(Path(module.__file__).resolve()):digest(Path(module.__file__)) for module in (source_headers,configured_fidl,library_dependencies,libmd_paths,static_sources,source_compile_flags,link_group_inventory,configured_tests,configured_rpc,configured_lexyacc,configured_libmd,configured_nls,component_plans,component_labels,program_compile,library_link_sequence,native_link_options,shared_modules)}
    for helper in ('native_cc.bzl','bsd_dtrace.bzl','bsd_fidl.bzl','source_identity.bzl'):
        path=Path(__file__).with_name(helper);sources[str(path.resolve())]=digest(path)
    if any(c.get('dtrace_providers') for c in data['components']):
        lines.append('load("//:bsd_dtrace.bzl", "bsd_dtrace_header")')
        runner=Path(__file__).with_name('copy_then_exec.c')
        shutil.copyfile(runner,out/runner.name);sources[str(runner)]=digest(runner)
        lines.append('cc_binary(name="dtrace_copy_runner", srcs=["copy_then_exec.c"], linkstatic=True, features=["fully_static_link"])')
    version_rule=Path(__file__).with_name('configured_version_map.bzl')
    shutil.copyfile(version_rule,out/version_rule.name)
    sources[str(version_rule)]=digest(version_rule)
    version_module=Path(configured_version_map.__file__)
    sources[str(version_module)]=digest(version_module)
    lines.insert(0,'load("//:configured_version_map.bzl", "bsd_configured_version_map")')
    filter_rule=Path(__file__).with_name('bsd_version_filter.bzl')
    shutil.copyfile(filter_rule,out/filter_rule.name);sources[str(filter_rule)]=digest(filter_rule)
    lines.insert(0,'load("//:bsd_version_filter.bzl", "bsd_version_filter")')
    def copy(p):
        relative=Path('sources')/p.relative_to(src);dest=out/relative
        if not dest.exists():dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
        sources[str(p)]=digest(p)
        if digest(dest)!=sources[str(p)]:raise ValueError('source snapshot mismatch')
        return '//:'+str(relative)
    def rule(rule_name,**values):lines.append(rule_name+'('+', '.join(k+'='+repr(v) for k,v in values.items())+')')
    groups={c['component']:link_group_inventory.resolve(c,data['components'],src)
            for c in data['components'] if c.get('shared_link_script')}
    selected_libraries=library_dependencies.component_index(data['components'])
    root_lines=lines
    component_lines={}
    base_loads=[line for line in lines if line.startswith('load(')]
    for c in data['components']:
        m=c['metadata'];shared_only=not m['LIB'] and not m['PROG'] and bool(m['SHLIB_NAME'])
        name=m['LIB'] or m['PROG'] or m['SHLIB_NAME']
        identity=(c['component'],name)
        if not name or identity in targets:raise ValueError('ambiguous component target')
        targets.add(identity)
        lines=component_lines.setdefault(c['component'],list(base_loads))
        (out/component_labels.package(c)).mkdir(parents=True,exist_ok=True)
        if m.get('ARADD'):raise ValueError('ARADD requires explicit native archive input support')
        if (m.get('STATIC_CFLAGS') or m.get('STATIC_CXXFLAGS')) and (not m['LIB'] or c.get('fidl_bindings')):raise ValueError('static compile flags require source-context support')
        if c.get('fidl_bindings') and not m['LIB']:raise ValueError('FIDL programs require explicit C++ program integration')
        providers=c.get('dtrace_providers',[])
        configuration=c.get('dtrace_configuration')
        generated_headers={p['header'] for p in providers}
        if providers and (not m['LIB'] or len(providers)!=1 or not configuration):
            raise ValueError('DTrace emission currently requires one configured library provider')
        if len(generated_headers)!=len(providers):raise ValueError('duplicate generated provider header')
        binding_labels,generated_directories,binding_outputs=configured_fidl.emit(c,receipt,src,copy,rule)
        if binding_outputs & generated_headers:raise ValueError('conflicting FIDL and DTrace output paths')
        if binding_labels:
            load='load("//:bsd_fidl.bzl", "bsd_fidl_ir", "bsd_fidl_bindings")'
            if load not in lines:lines.insert(0,load)
        catalogue_labels=configured_nls.emit(c,receipt,src,copy,rule)
        if catalogue_labels:
            helper=Path(__file__).with_name('bsd_nls.bzl')
            shutil.copyfile(helper,out/helper.name);sources[str(helper)]=digest(helper)
            load='load("//:bsd_nls.bzl", "bsd_catalogue")'
            if load not in lines:lines.insert(0,load)
        rpc_outputs,rpc_headers=configured_rpc.emit(c,receipt,src,Path(data['build_environment']['objtop']),copy,rule)
        if rpc_outputs:
            generated_directories[c['rpc_generation']['generated_include_directory']]=component_labels.generated_directory(c,'generated/'+name)
            if not m['LIB']:raise ValueError('RPC program compilation requires generated-header integration')
            if set(rpc_outputs) & (generated_headers | binding_outputs):raise ValueError('conflicting RPC output')
            if set(rpc_outputs)!={r['name'] for r in c['sources'] if r['resolution']=='generated-rpc'}:
                raise ValueError('RPC output inventory differs from configured sources')
            helper=Path(__file__).with_name('bsd_rpcgen.bzl')
            shutil.copyfile(helper,out/helper.name);sources[str(helper.resolve())]=digest(helper)
            load='load("//:bsd_rpcgen.bzl", "bsd_rpcgen")'
            if load not in lines:lines.insert(0,load)
        parser_outputs,parser_headers=configured_lexyacc.emit(c,receipt,src,copy,rule)
        if parser_outputs:
            if not m['LIB']:raise ValueError('lexer/parser program compilation requires generated-header integration')
            if set(parser_outputs) & (generated_headers | binding_outputs | set(rpc_outputs)):raise ValueError('conflicting parser output')
            if set(parser_outputs)!={r['name'] for r in c['sources'] if r['resolution']=='generated-lexyacc'}:raise ValueError('parser output inventory differs from configured sources')
            helper=Path(__file__).with_name('bsd_lexyacc.bzl')
            shutil.copyfile(helper,out/helper.name);sources[str(helper.resolve())]=digest(helper)
            load='load("//:bsd_lexyacc.bzl", "bsd_lexyacc")'
            if load not in lines:lines.insert(0,load)
            generated_directories[c['lexyacc_generation']['generated_include_directory']]=component_labels.generated_directory(c,'generated/'+name)
        generated_headers.update(n for n in parser_outputs if n.endswith('.h'))
        generated_headers.update(n for n in rpc_outputs if n.endswith('.h'))
        digest_outputs,digest_headers=configured_libmd.emit(c,receipt,src,out,copy,rule,sources)
        if digest_outputs:
            helper=Path(__file__).with_name('libmd_graph.bzl')
            shutil.copyfile(helper,out/helper.name);sources[str(helper.resolve())]=digest(helper)
            load='load("//:libmd_graph.bzl", "libmd_generated")'
            if load not in lines:lines.insert(0,load)
            generated_headers.update(r['name'] for r in c['digest_generation']['headers'])
            if set(digest_outputs)!={r['name'] for r in c['sources'] if r['resolution']=='generated-digest'}:raise ValueError('digest output inventory differs')
        source_records=[record for record in c['sources'] if record['name'] not in generated_headers | binding_outputs]
        # bsd.lib.mk/bsd.prog.mk exclude *.h from object construction while
        # retaining them as dependency inputs. Preserve explicitly listed headers
        # even when they live outside the normal include-root snapshot.
        declared_headers=[record for record in source_records if record['name'].endswith('.h')]
        source_records=[record for record in source_records if not record['name'].endswith('.h')]
        declared_header_labels=list(digest_headers)
        for record in declared_headers:
            if record['resolution']!='source':raise ValueError('header requires declared generation: '+c['component']+': '+record['name'])
            path=src/record['path']
            if not path.resolve().is_relative_to(src) or digest(path)!=record['sha256']:
                raise ValueError('configured header differs from component inventory')
            declared_header_labels.append(copy(path))
        provider_labels=[]
        if providers:
            if configuration['flags']!=['-C','-x','nolibs']:
                raise ValueError('DTrace preprocessing options require additional declared input mapping')
            selected=configuration['executable'];role='extra_dtrace'
            if receipt['tool_origins'].get(role)!=selected['path'] or receipt['inputs'].get(selected['path'])!=selected['sha256']:
                raise ValueError('selected DTrace differs from staged execution tool')
            sdk=Path(data['build_environment']['objtop'])/'tmp'
            drti=Path(configuration['drti']['path'])
            if not drti.is_relative_to(sdk):raise ValueError('target drti is outside selected SDK')
            drti_relative='toolchain/sysroot/'+str(drti.relative_to(sdk))
            if receipt['snapshot'].get(drti_relative)!=configuration['drti']['sha256']:
                raise ValueError('DTrace target runtime differs from staged SDK')
            generated_directories[configuration['generated_include_directory']]=component_labels.generated_directory(c,'generated/'+name)
            for index,provider in enumerate(providers):
                path=src/provider['path']
                if digest(path)!=provider['sha256']:raise ValueError('DTrace provider changed')
                label=name+'_dtrace_'+str(index);provider_labels.append(':'+label)
                rule('bsd_dtrace_header',name=label,source=copy(path),output='generated/'+name+'/'+provider['header'],
                    flags=configuration['flags'],static_anchor=configuration['static_anchor'],object_path_mode='relative',
                    dtrace='//toolchain:'+role,cpp='//toolchain:bin/cpp',linker='//toolchain:bin/ld.lld',objcopy='//toolchain:bin/llvm-objcopy',
                    drti='//toolchain:sysroot/'+str(drti.relative_to(sdk)),
                    tool_inputs=['//toolchain:'+role+'_runtime','//toolchain:compile_inputs','//toolchain:link_inputs','//toolchain:objcopy_inputs'])
        if m['MK_CTF']!='no':raise ValueError('CTF requires explicit support')
        if bool(m['SYMBOL_MAPS'])!=bool(c.get('generated_version_map')):raise ValueError('generated symbol map lacks configuration inventory')
        if any(s['resolution'] not in ('source','source-alias','generated-syscall','generated-rpc','generated-lexyacc','generated-digest') or not s['name'].endswith(('.c','.cc','.cpp','.cxx','.C','.S')) for s in source_records):raise ValueError('unresolved source or unsupported language in component graph')
        if m['PROG'] and any(s['name'].endswith('.S') for s in source_records):
            raise ValueError('assembly programs require explicit configured compile support')
        has_cxx=bool(binding_labels) or any(s['name'].endswith(('.cc','.cpp','.cxx','.C')) for s in source_records)
        link_deps=list(dict.fromkeys(library_dependencies.component_link_labels(c,data['components'],dynamic=True,sequence=bool(m['PROG']))))
        static_link_deps=library_dependencies.component_link_labels(c,data['components'],dynamic=False) if m['LIB'] else []
        group_members=groups.get(c['component'],[])
        link_group=bool(group_members)
        if bool(m.get('SHLIB_LDSCRIPT'))!=link_group:raise ValueError('shared linker script lacks validated group inventory')
        if link_group:
            script=c['shared_link_script']
            script_rule=Path(__file__).with_name('bsd_link_script.bzl')
            shutil.copyfile(script_rule,out/script_rule.name);sources[str(script_rule.resolve())]=digest(script_rule)
            load='load("//:bsd_link_script.bzl", "bsd_link_script")'
            if load not in lines:lines.insert(0,load)
            rule('bsd_link_script',name=name+'_link_script',template=copy(src/script['template']['path']),
                output=script['output'],substitutions=script['substitutions'])
        paths=[];labels=[]
        syscall=c.get('syscall_generation')
        generated={v['name']:v for v in syscall['outputs']} if syscall else {}
        if set(generated)!={v['name'] for v in source_records if v['resolution']=='generated-syscall'}:
            raise ValueError('syscall generation inventory differs from selected sources')
        if syscall:
            generator=src/syscall['generator']['path']
            if not generator.resolve().is_relative_to(src) or digest(generator)!=syscall['generator']['sha256']:
                raise ValueError('syscall generator changed')
            generator_label=copy(generator)
            helper=Path(__file__).with_name('bsd_syscall_asm.bzl')
            shutil.copyfile(helper,out/helper.name);sources[str(helper.resolve())]=digest(helper)
            load='load("//:bsd_syscall_asm.bzl", "bsd_syscall_asm")'
            if load not in lines:lines.insert(0,load)
        for record in source_records:
            if record['resolution']=='source':
                path=src/record['path']
                if not path.resolve().is_relative_to(src) or digest(path)!=record['sha256']:
                    raise ValueError('selected source differs from component inventory: '+str(path))
                paths.append(path);labels.append(copy(path))
            elif record['resolution']=='generated-digest':
                labels.append(digest_outputs[record['name']])
            elif record['resolution']=='generated-lexyacc':
                labels.append(parser_outputs[record['name']])
            elif record['resolution']=='generated-rpc':
                labels.append(rpc_outputs[record['name']])
            elif record['resolution']=='source-alias':
                path=src/record['path']
                if not path.resolve().is_relative_to(src) or digest(path)!=record['sha256']:
                    raise ValueError('source alias input changed')
                paths.append(path)
                output='generated/'+name+'/aliases/'+record['name']
                rule('bsd_source_alias',name=name+'_alias_'+record['name'],source=copy(path),output=output)
                labels.append(output)
            else:
                output='generated/'+name+'/'+record['name']
                rule('bsd_syscall_asm',name=name+'_generate_'+record['name'],output=output,
                    generator=generator_label,arguments=generated[record['name']]['arguments'],
                    shell='//toolchain:sh',redirect='//toolchain:stdout_redirect',runtime=['//toolchain:sh_runtime'])
                labels.append(output)
        copts,includes=rewrite_includes(shlex.split(m['CFLAGS']),src,Path(data['build_environment']['objtop']),generated_directories=generated_directories)
        cxxopts=[]
        if has_cxx:
            cxxopts,cxxincludes=rewrite_includes(shlex.split(m['CXXFLAGS']),src,Path(data['build_environment']['objtop']),generated_directories=generated_directories)
            includes+=cxxincludes
        static_labels,static_headers=static_sources.emit(c,src,Path(data['build_environment']['objtop']),copy,rule,generated_directories)
        context_flags,context_headers=source_compile_flags.emit(source_records,labels,src,Path(data['build_environment']['objtop']),generated_directories)
        archive_object_names={label+'|'+variant:Path(context['target']).name
            for record,label in zip(source_records,labels,strict=True)
            for variant,context in record.get('compile_contexts',{}).items()}
        header_dirs=set(includes)|{p.parent for p in paths}|static_headers
        absent_includes.update(d for d in header_dirs if not d.exists())
        absent_includes.update(d for directories in context_headers.values() for d in directories if not d.exists())
        headers=sorted(set(declared_header_labels) | {copy(p) for d in header_dirs for p in source_headers.collect(d) if p.is_file()})
        textual_inputs=set();source_textual_inputs={}
        for record,label in zip(source_records,labels,strict=True):
            # File-specific include roots must not become public inputs of
            # every source or leak into downstream compilation contexts.
            selected=sorted({copy(p) for directory in context_headers.get(label,set())-header_dirs
                             for p in source_headers.collect(directory) if p.is_file()})
            for entry in record.get('textual_inputs',[]):
                path=src/entry['path']
                if not path.resolve().is_relative_to(src) or digest(path)!=entry['sha256']:
                    raise ValueError('textual source input changed')
                selected.append(copy(path))
            if selected:
                source_textual_inputs[label]=selected;textual_inputs.update(selected)
        per={}
        supported=set()
        for record in c['sources']:
            source=record['name'];keys=['CWARNFLAGS.'+source,('CXXFLAGS.' if source.endswith(('.cc','.cpp','.cxx','.C')) else 'CFLAGS.')+source]
            supported.update(keys)
            if record.get('compile_contexts'):
                supported.update(prefix+source for prefix in ('CFLAGS.','CXXFLAGS.','CWARNFLAGS.','CXXWARNFLAGS.','ACFLAGS.'))
                supported.update(prefix+str(Path(source).with_suffix(suffix)) for prefix in ('CFLAGS.','CWARNFLAGS.','ACFLAGS.') for suffix in ('.o','.pico','.pieo','.nossppico'))
                continue
            flags=shlex.split(' '.join(c['per_file_flags'].get(k,'') for k in keys))
            if flags:
                if source in generated_headers:raise ValueError('generated header has unsupported per-file compilation flags')
                if not m['LIB']:raise ValueError('per-file program flags require explicit compile support')
                rewritten,extra_includes=rewrite_includes(flags,src,Path(data['build_environment']['objtop']),generated_directories=generated_directories)
                if extra_includes:raise ValueError('per-file include directories require explicit header closure')
                per[Path(source).name]=rewritten
        for key,value in c['per_file_flags'].items():
            if key not in supported and value.strip():raise ValueError('per-target flags require variant support: '+key)
        generators=c.get('generators',[])
        if {g['output'] for g in generators}!=set(shlex.split(m['PCFILES'])+shlex.split(m.get('CONF_GENERATED',''))):
            raise ValueError('template generation inventory differs from metadata')
        for generator in generators:
            tools=generator['tools']
            if any(t not in receipt['tool_origins'] for t in tools):
                raise ValueError('template tool lacks selected SDK mapping')
            rule('bsd_template',name=name+'_generate_'+generator['output'],script=copy(src/generator['script']),template=copy(src/generator['template']),output='generated/'+name+'/'+generator['output'],dependencies=[copy(src/p) for p in generator['dependencies']],shell='//toolchain:sh',tools=['//toolchain:bin/'+t for t in tools],execution_runtime=['//toolchain:'+t+'_runtime' for t in ['sh',*tools]],arguments=generator['arguments'])
        if m['LIB'] or shared_only:
            if not shared_only:
                if shlex.split(m['ARFLAGS'])!=['-crsD']:raise ValueError('unsupported archive policy')
                configured=set(shlex.split(m['_LIBS']))
                archive_basename='lib'+m.get('LIB_PRIVATE','')+name
                regular=archive_basename+'.a';pie=archive_basename+'_pie.a';pic=archive_basename+'_pic.a'
                nossp=archive_basename+'_nossp_pic.a'
                allowed={regular,pie,pic,nossp,m['SHLIB_NAME']}-{''}
                if regular not in configured or configured-allowed:
                    raise ValueError('unsupported configured library outputs: '+repr(sorted(configured)))
                has_shared=bool(m['SHLIB_NAME']) and m['SHLIB_NAME'] in configured
                variants=['regular'];variant_flags={};cxx_variant_flags={}
                if has_shared or pic in configured:
                    variants.append('pic')
                    variant_flags['pic']=shlex.split(m['PICFLAG'])+['-DPIC']+shlex.split(m['SHARED_CFLAGS'])
                    cxx_variant_flags['pic']=shlex.split(m['PICFLAG'])+['-DPIC']+shlex.split(m['SHARED_CXXFLAGS'])
                if pie in configured:
                    variants.append('pie')
                    variant_flags['pie']=shlex.split(m['PIEFLAG'])+['-DPIC']+shlex.split(m['SHARED_CFLAGS'])
                    cxx_variant_flags['pie']=shlex.split(m['PIEFLAG'])+shlex.split(m['SHARED_CXXFLAGS'])
                if nossp in configured:
                    variants.append('nossp_pic')
                object_keys={'regular':'OBJS','pic':'SOBJS','pie':'PIEOBJS','nossp_pic':'NOSSPSOBJS'}
                # ar -crsD stores basenames, including for object paths in subdirectories.
                # The native rule still rejects basename collisions and incomplete coverage.
                member_order={variant:[Path(obj).name for obj in shlex.split(m[object_keys[variant]])+
                    (shlex.split(m['STATICOBJS']) if variant=='regular' else [])] for variant in variants}
                dtrace_object_names={}
                if providers:
                    stem=Path(providers[0]['name']).stem
                    suffixes={'regular':'.o','pic':'.pico','pie':'.pieo','nossp_pic':'.nossppico'}
                    for variant in variants:
                        member=stem+suffixes[variant]
                        if member not in member_order[variant]:raise ValueError('DTrace object absent from configured archive inventory')
                        dtrace_object_names[variant]=member
                rule('bsd_library',name=name,archive_basename=archive_basename,srcs=labels,source_keys={label:label for label in labels},textual_keys={label:label for label in textual_inputs},hdrs=headers,generated_headers=rpc_headers+parser_headers,copts=copts,cxxopts=cxxopts,fidl_bindings=binding_labels,static_sources=static_labels,source_variant_flags=context_flags,source_variants={label:list(record['compile_contexts']) for record,label in zip(source_records,labels,strict=True)},archive_object_names=archive_object_names,archive_member_order=member_order,dtrace_object_names=dtrace_object_names,textual_inputs=sorted(textual_inputs),source_textual_inputs=source_textual_inputs,arflags=['-crsD'],archive_inputs='//toolchain:archive_inputs',deps=static_link_deps,per_file_flags=per,variants=variants,variant_flags=variant_flags,cxx_variant_flags=cxx_variant_flags,**({'dtrace_providers':provider_labels,'dtrace_copy_runner':'//:dtrace_copy_runner'} if providers else {}))
                if 'pie' in variants:
                    rule('filegroup',name=name+'_pie',srcs=[':'+name],output_group='pie_archive')
                if 'pic' in variants:
                    rule('filegroup',name=name+'_pic',srcs=[':'+name],output_group='pic_archive')
                if 'nossp_pic' in variants:
                    rule('filegroup',name=name+'_nossp_pic',srcs=[':'+name],output_group='nossp_pic_archive')
                for variant in ('pic','pie','nossp_pic'):
                    if variant in variants:
                        rule('cc_import',name=name+'_'+variant+'_link_object',static_library=':'+name+'_'+variant)
                        rule('cc_library',name=name+'_'+variant+'_link',deps=[':'+name+'_'+variant+'_link_object']+link_deps)
                if not has_shared:
                    rule('cc_import',name=name+'_regular_link_object',static_library=':'+name)
                    rule('cc_library',name=library_dependencies.shared_link_target(m),deps=[':'+name+'_regular_link_object']+link_deps)
                    continue
                rule('cc_import',name=name+'_whole',static_library=':'+name+'_pic',alwayslink=True)
            else:
                if link_group:
                    raise ValueError('shared-only linker groups require explicit support')
                order, module_flags = shared_modules.inventory(c, source_records, labels, context_flags)
                program_rule=Path(__file__).with_name('bsd_program.bzl')
                sources[str(program_rule.resolve())]=digest(program_rule)
                shutil.copyfile(program_rule,out/program_rule.name)
                lines.insert(0,'load("//:bsd_program.bzl", "bsd_program_objects")')
                rule('bsd_program_objects',name=name+'_objects',srcs=labels,
                     source_keys={label:label for label in labels},
                     textual_keys={label:label for label in textual_inputs},
                     source_order=order,source_flags=module_flags,position_independent=True,
                     hdrs=headers,textual_inputs=sorted(textual_inputs),
                     source_textual_inputs=source_textual_inputs,deps=link_deps)
            opts=[x for x in shlex.split(m['LDFLAGS']+' '+m['SSP_CFLAGS']+' '+m['SOLINKOPTS']) if x!='-shared']
            linker_inputs=[]
            version=c.get('version_map');generated_version=c.get('generated_version_map')
            version_filter=c.get('version_filter')
            if sum(v is not None for v in (version,generated_version,version_filter))>1:raise ValueError('ambiguous version map policy')
            label=None
            if generated_version is not None:
                def version_input(record):
                    origin=src/record['path']
                    if not origin.resolve().is_relative_to(src) or digest(origin)!=record['sha256']:raise ValueError('version generator input changed')
                    return copy(origin)
                rule('bsd_configured_version_map',name=name+'_versions',symbol_maps=[version_input(v) for v in generated_version['symbols']],versions=version_input(generated_version['versions']),generator=version_input(generated_version['generator']),headers=headers+provider_labels,cpp_flags=configured_version_map.cpp_flags(generated_version['cpp_command'],Path(data['build_environment']['objtop']),generated_version['compiler_resource']),copts=copts,compiler='//toolchain:bin/clang',compiler_inputs='//toolchain:compile_inputs',cat='//toolchain:cat',cat_runtime='//toolchain:cat_runtime',awk='//toolchain:awk',awk_runtime='//toolchain:awk_runtime',redirect='//toolchain:stdout_redirect')
                label=':'+name+'_versions'
            elif version_filter is not None:
                template=version_filter['template'];origin=src/template['path']
                if not origin.resolve().is_relative_to(src) or digest(origin)!=template['sha256']:raise ValueError('version filter template changed')
                if 'sed' not in receipt['tool_origins']:raise ValueError('version filter requires staged sed')
                rule('bsd_version_filter',name=name+'_versions',template=copy(origin),output='generated/'+name+'/'+version_filter['output'],arguments=version_filter['arguments'],sed='//toolchain:sed',redirect='//toolchain:stdout_redirect',runtime=['//toolchain:sed_runtime'])
                label=':'+name+'_versions'
            elif version is not None:
                origin=src/version['path']
                if digest(origin)!=version['sha256']:raise ValueError('version map input changed')
                label=copy(origin)
            if label is not None:
                expected='-Wl,--version-script='+m['VERSION_MAP']
                if opts.count(expected)!=1:raise ValueError('configured version-map linker option missing or ambiguous')
                opts=[('-Wl,--version-script=$(location '+label+')') if flag==expected else flag for flag in opts]
                linker_inputs.append(label)
            elif any('--version-script' in flag for flag in opts):
                raise ValueError('version-script option lacks declared map')
            opts,translated_search=native_link_options.translate(c,data['components'],opts,src,Path(data['build_environment']['objtop']))
            if translated_search:
                (out/component_labels.package(c)/(name+'-link-search.json')).write_text(json.dumps(dict(configured_search_directories=translated_search,native_dependencies=link_deps,scope='configured shared-library search replaced by declared native artifacts'),indent=2)+'\n')
            if has_cxx:
                if any(key not in m for key in ('CC','CXX','_LD')):raise ValueError('C++ link policy missing; regenerate component plan')
                if m['_LD']==m['CXX']:opts+=['--driver-mode=g++']
                elif m['_LD']!=m['CC']:raise ValueError('custom library link driver requires explicit toolchain support')
            opts+=['-Wl,-soname,'+m['SONAME']]
            rule('cc_binary',name=m['SHLIB_NAME_FULL'],srcs=[':'+name+'_objects'] if shared_only else [],deps=([] if shared_only else [':'+name+'_whole'])+link_deps,linkshared=True,linkstatic=True,linkopts=opts,additional_linker_inputs=linker_inputs)
            rule('bsd_shared_alias',name=name+'_soname',library=':'+m['SHLIB_NAME_FULL'],output=m['SHLIB_NAME'])
            if shared_only and any(test.get('test_interface') and test['metadata']['BINDIR']==m['SHLIBDIR'] for test in data['components']):
                # Keep suite-relative loader paths out of installed module outputs.
                rule('cc_binary',name=name+'_native_test_module',srcs=[':'+name+'_objects'],
                     deps=link_deps,linkshared=True,linkstatic=True,
                     linkopts=opts+['-Wl,--disable-new-dtags','-Wl,-rpath,$$ORIGIN'],additional_linker_inputs=linker_inputs,
                     features=['bsd_test_runtime_paths'])
                rule('bsd_shared_alias',name=name+'_suite_module',library=':'+name+'_native_test_module',
                     output='test/'+m['SHLIB_NAME'])
            if not link_group:
                rule('cc_import',name=name+'_dynamic',shared_library=':'+name+'_soname')
            if link_group:
                native_rule=Path(__file__).with_name('bsd_link_group.bzl')
                shutil.copyfile(native_rule,out/native_rule.name);sources[str(native_rule.resolve())]=digest(native_rule)
                load='load("//:bsd_link_group.bzl", "bsd_link_group")'
                if load not in lines:lines.insert(0,load)
                members=[];group_deps=[]
                for member in group_members:
                    owner=member['library'];variant=member['variant']
                    members.append(component_labels.label(member['component'],owner+('_soname' if member['kind']=='shared' else '' if variant=='regular' else '_'+variant)))
                    for dependency in library_dependencies.component_link_labels(selected_libraries[member['component']],data['components'],dynamic=True):
                        if dependency not in group_deps:group_deps.append(dependency)
                rule('bsd_link_group',name=name+'_native_group',members=members,
                     shared_member_indices=[i for i,member in enumerate(group_members) if member['kind']=='shared'])
                rule('cc_library',name=name+'_dynamic',deps=[':'+name+'_native_group']+group_deps)
        else:
            program_opts,translated_search=library_dependencies.program_link_options(c,data['components'],src,Path(data['build_environment']['objtop']),sequence=True)
            runtime_deps=library_dependencies.program_runtime_labels(program_runtimes,data['components'],program_opts)
            for dependency in runtime_deps:
                if dependency not in link_deps:link_deps.append(dependency)
            selections=library_link_sequence.resolve(c,data['components'])
            artifact_sequence=library_link_sequence.artifacts(selections,data['components'])
            binary_deps=[]
            if artifact_sequence:
                sequence_rule=Path(__file__).with_name('bsd_link_sequence.bzl')
                sources[str(sequence_rule.resolve())]=digest(sequence_rule)
                shutil.copyfile(sequence_rule,out/sequence_rule.name)
                load='load("//:bsd_link_sequence.bzl", "bsd_link_sequence")'
                if load not in lines:lines.insert(0,load)
                member_indices={};members=[];order=[]
                for artifact in artifact_sequence:
                    if artifact not in member_indices:
                        member_indices[artifact]=len(members);members.append(artifact)
                    order.append(member_indices[artifact])
                rule('bsd_link_sequence',name=name+'_library_sequence',members=members,order=order)
                binary_deps.append(':'+name+'_library_sequence')
            binary_deps+=runtime_deps
            if translated_search:
                (out/component_labels.package(c)/(name+'-link-search.json')).write_text(json.dumps(dict(configured_search_directories=translated_search,native_dependencies=link_deps,scope='configured -l dependencies replaced by explicit Bazel linker inputs; SDK controls target runtime'),indent=2)+'\n')
            program_rule=Path(__file__).with_name('bsd_program.bzl')
            sources[str(program_rule.resolve())]=digest(program_rule)
            shutil.copyfile(program_rule,out/program_rule.name)
            load='load("//:bsd_program.bzl", "bsd_program_objects")'
            if load not in lines:lines.insert(0,load)
            order,program_flags=program_compile.inventory(c,source_records,labels,context_flags)
            rule('bsd_program_objects',name=name+'_objects',srcs=labels,source_keys={label:label for label in labels},
                 textual_keys={label:label for label in textual_inputs},source_order=order,
                 source_flags=program_flags,hdrs=headers,textual_inputs=sorted(textual_inputs),
                 source_textual_inputs=source_textual_inputs,deps=link_deps)
            driver,flag_key=program_compile.link_driver(m)
            driver_flags,_=rewrite_includes([v for v in shlex.split(m[flag_key]) if not v.startswith('-M')],
                src,Path(data['build_environment']['objtop']),generated_directories=generated_directories)
            program_opts=['--driver-mode='+driver]+driver_flags+program_opts
            rule('cc_binary',name=name,srcs=[':'+name+'_objects'],deps=binary_deps,linkopts=program_opts,linkstatic=False)
            if c.get('test_interface'):
                if c['test_interface']!='atf':raise ValueError('configured test interface requires explicit runner support')
                test_binary=name+'_native_test_program'
                # Kyua stages declared SONAME symlinks beside this test executable.
                # Explicit sequence flags do not populate Bazel's automatic
                # solib search list. Keep this path out of installed binaries.
                rule('cc_binary',name=test_binary,srcs=[':'+name+'_objects'],deps=binary_deps,linkopts=program_opts+['-Wl,--disable-new-dtags','-Wl,-rpath,$$ORIGIN'],linkstatic=False,features=['bsd_test_runtime_paths'])
                configured_test_records.append((c,test_binary))
        # Mirror maintained debug extraction and installation strip policy.
        linked=m['SHLIB_NAME_FULL'] if m['LIB'] or shared_only else name
        installed=m['SHLIB_NAME'] if m['LIB'] or shared_only else name
        runtime=':'+linked
        if m['MK_DEBUG_FILES'] not in ('yes','no'):
            raise ValueError('unsupported debug policy')
        if m['MK_DEBUG_FILES']=='yes':
            debug=m['DEBUGFILE']
            if not debug or Path(debug).name!=debug:
                raise ValueError('debug output must be a configured basename')
            rule('bsd_debug_split',name=name+'_split',src=runtime,
                 binary_name='split/'+name+'/'+installed,
                 debug_name='split/'+name+'/'+debug,
                 objcopy='//toolchain:bin/llvm-objcopy',
                 objcopy_inputs='//toolchain:objcopy_inputs')
            rule('filegroup',name=name+'_debug',srcs=[':'+name+'_split'],output_group='debug_files')
            runtime=':'+name+'_split'
        if shlex.split(m['STRIP'])==['-s']:
            rule('bsd_strip_binary',name=name+'_runtime_install',src=runtime,
                 output='install/'+name+'/'+installed,
                 strip='//toolchain:bin/llvm-strip',strip_inputs='//toolchain:strip_inputs')
        elif not m['STRIP'].strip():
            rule('alias',name=name+'_runtime_install',actual=runtime)
        else:
            raise ValueError('unsupported maintained installation strip policy')
    lines=root_lines
    policies = [(p, None) for p in a.component_install_plan]
    if a.library_install_plan is not None:
        policies.append((a.library_install_plan, 'library'))
    if policies:
        if a.compression_tools is None:
            raise ValueError('installation requires declared compression tools')
        for name in ('bsd_install.bzl', 'bsd_kyua_metadata.bzl'):
            install_rule = Path(__file__).with_name(name)
            sources[str(install_rule.resolve())] = digest(install_rule)
            shutil.copyfile(install_rule,out/name)
        lines.insert(0,'load("//:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")')
        seen_components=set()
        manifest_labels=[]
        for policy_path, namespace in policies:
            policy=json.loads(policy_path.read_text())
            selected=[c for c in data['components'] if c['component']==policy.get('component')]
            if len(selected)!=1 or policy['component'] in seen_components:
                raise ValueError('installation must select one unique configured component')
            seen_components.add(policy['component'])
            c=selected[0];name=c['metadata']['LIB'] or c['metadata']['PROG']
            if namespace=='library' and not c['metadata']['LIB']:
                raise ValueError('library installation option requires a library')
            library=dict(c,source_root=str(src),build_environment=data['build_environment'])
            labels={'static_archive':':'+name,'pic_archive':':'+name+'_pic','shared_library':':'+name+'_runtime_install',
                    'shared_debug':':'+name+'_debug','shared_link_script':':'+name+'_link_script','program':':'+name+'_runtime_install',
                    'program_debug':':'+name+'_debug'}
            labels.update({'generated:'+g['output']:':'+name+'_generate_'+g['output'] for g in c['generators']})
            manifest_labels.append(component_labels.label(c,(namespace or name)+'_install_manifest'))
            labels.update({'catalogue:'+g['name']:':'+name+'_catalogue_'+g['name'] for g in (c.get('nls_generation') or {}).get('outputs',[])})
            emitted=library_install.emit(out/component_labels.package(c),policy_path,a.compression_tools,library,labels,namespace or name)
            # Multiple component policies share the same rule definitions.
            target_lines=component_lines[c['component']]
            target_lines.insert(0,'load("//:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")')
            target_lines.extend(line for line in emitted if line not in target_lines or not line.startswith('load('))
    elif a.compression_tools is not None:
        raise ValueError('compression tools require installation policy')
    if a.directory_policy is not None or a.install_tools is not None:
        if a.directory_policy is None or a.install_tools is None or not policies:
            raise ValueError('staging requires directory policy, installer and payload policies')
        lines.extend(stage_install.emit(out,a.directory_policy,a.install_tools,
            {'build_environment':data['build_environment']},
            payload_policies=[p for p,_ in policies],manifest_labels=manifest_labels))
    if a.test_config is not None:
        suite=json.loads(a.test_config.read_text()).get('suite')
        if suite=='bzip2':lines.extend(bzip2_tests.emit(out,data,a.test_config,src))
        elif suite in ('native-c','native-cxx','native-tap','native-atf'):lines.extend(native_c_tests.emit(out,data,a.test_config,src,groups=groups))
        else:raise ValueError('unsupported explicit native test suite')
    for component,emitted in configured_tests.emit(out,data['components'],configured_test_records,groups=groups,program_runtimes=program_runtimes).items():
        target_lines=component_lines[component]
        target_lines.extend(line for line in emitted if not line.startswith('load(') or line not in target_lines)
    visibility='package(default_visibility = ["//visibility:public"])'
    def render(entries):
        loads=list(dict.fromkeys(line for line in entries if line.startswith('load(')))
        return '\n\n'.join(loads+[visibility]+[line for line in entries if not line.startswith('load(')])+'\n'
    for component,target_lines in component_lines.items():
        (out/component_labels.package(component)/'BUILD.bazel').write_text(render(target_lines))
    exported=[str(path.relative_to(out)) for path in (out/'sources').rglob('*') if path.is_file()]
    exported += [name for name in ('copy_then_exec.c','libmd_environment.py','elf-runtime-check.py') if (out/name).is_file()]
    lines += ['exports_files('+repr(sorted(exported))+')']
    (out/'BUILD.bazel').write_text(render(lines))
    (out/'MODULE.bazel').write_text('module(name="bsd_components")\nbazel_dep(name="rules_cc", version="0.2.17")\nbazel_dep(name="platforms", version="1.0.0")\nregister_toolchains("//toolchain:registered")\n')
    if any(path.exists() for path in absent_includes):
        raise ValueError('absent source include directory appeared during emission')
    for p,h in {**data['input_sha256'],**sources}.items():
        if digest(Path(p))!=h:raise ValueError('input changed while emitting graph: '+p)
    (out.parent/(out.name+'-inputs.json')).write_text(json.dumps({'format':1,'component_plan':str(a.plan),'component_plan_sha256':digest(a.plan),'component_plans':data['component_plans'],'program_runtime_libraries':program_runtimes,'source_inputs':sources,'absent_source_include_directories':sorted(str(p) for p in absent_includes),'scope':'native C/C++ library, C program and declared generator build graph; installation/package parity not qualified'},indent=2)+'\n')
    print(out)
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('src','plan','toolchain-receipt','toolchain-workspace','module-lock','output'):p.add_argument('--'+k,type=Path,required=True)
    p.add_argument('--additional-plan',type=Path,action='append',default=[])
    p.add_argument('--test-config',type=Path)
    p.add_argument('--library-install-plan',type=Path)
    p.add_argument('--compression-tools',type=Path)
    p.add_argument('--program-runtime-library',action='append',default=[])
    p.add_argument('--component-install-plan',type=Path,action='append',default=[])
    p.add_argument('--directory-policy',type=Path)
    p.add_argument('--install-tools',type=Path)
    emit(p.parse_args())
