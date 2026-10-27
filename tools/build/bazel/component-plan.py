#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Export selected component metadata using a shared world configuration session.

This is configuration evidence, not a native build or package coverage claim.
"""
import argparse
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shlex
import shutil
import time
from libmd_environment import BuildEnvironment,digest
import configured_version_map
import shared_link_script
import configured_version_filter
import configured_lexyacc
import configured_libmd
import configured_rpc
import configured_nls
import configured_programs
import configured_source_aliases
import configured_variant_sources
import configured_build_tools
import configured_static_objects
import compile_context
import configured_syscalls

VARIABLES = ('MACHINE','MACHINE_ARCH','LIB','CC','CXX','_LD','LIB_PRIVATE','_LIBS','OBJS','SOBJS','PIEOBJS','NOSSPSOBJS','STATICOBJS','VARIANT_SOURCE_OBJECTS','ARADD','STATIC_CFLAGS','STATIC_CXXFLAGS','DTRACE_PROVIDERS','DTRACE','DTRACEFLAGS','_DTRACE_SYSROOT_FLAG','_DTRACE_DRTI_DEP','DTRACE_STATIC_ANCHOR','FIDL_BINDINGS','FIDLC','PYTHON','FIDL_AVAILABLE','_FIDLGEN_DIR','_FIDLGEN_TEMPLATES','_FIDLGEN_TOOLS','_FIDL_RUNTIME_HEADERS','PICFLAG','PIEFLAG','SHARED_CFLAGS','SHARED_CXXFLAGS','PROG','PROG_CXX','PROGS','PROGS_CXX','PACKAGE','LIB_PACKAGE','SRCS','.PATH','.OBJDIR','CFLAGS','CXXFLAGS','ACFLAGS','LDFLAGS','LDADD','LIBADD','DPADD','ARFLAGS','SOLINKOPTS','SSP_CFLAGS','SHLIB_NAME','SHLIB_LDSCRIPT','SHLIB_LINK','_LIBDIR','_SHLIBDIR','SHLIB_NAME_FULL','SHLIB_MAJOR','SONAME','DEBUGFILE','DEBUGFILEDIR','MK_DEBUG_FILES','STRIP','MK_CTF','INCS','MAN','MLINKS','LINKS','SYMLINKS','PCFILES','CONF_GENERATED','FILESGROUPS','CONFGROUPS','SCRIPTS','SUBDIR','SUBDIR_DEPEND','LIBDIR','SHLIBDIR','INCLUDEDIR','BINDIR','MANDIR','PCFILESDIR','LIBOWN','LIBGRP','LIBMODE','BINOWN','BINGRP','BINMODE','TAGS','SYMBOL_MAPS','VERSION_DEF','VERSION_MAP','.MAKE.MAKEFILES')

def export(args):
    jobs=getattr(args,'jobs',os.cpu_count() or 1)
    if jobs<1:raise ValueError('positive configuration worker count required')
    src=args.src.resolve(strict=True);out=args.output.resolve()
    if args.output.is_symlink() or out.exists() or not out.is_relative_to('/usr/obj') or out==Path('/usr/obj') or src.is_relative_to(out) or out.is_relative_to(src) or args.objtop.resolve().is_relative_to(out):
        raise ValueError('fresh nonoverlapping output below /usr/obj required')
    components=[]
    for value in args.component:
        p=Path(value)
        if p.is_absolute() or '..' in p.parts:raise ValueError('component must be source-relative')
        component=(src/p).resolve(strict=True)
        if not component.is_relative_to(src) or not (component/'Makefile').is_file():raise ValueError('component lacks source Makefile')
        if component in components:raise ValueError('duplicate component')
        components.append(component)
    start=time.monotonic()
    env=BuildEnvironment(src,args.objtop,args.profile,args.make,components[0])
    inputs=dict(env.inputs);inputs[str(Path(__file__).resolve())]=digest(Path(__file__))
    inputs[str(Path(__file__).with_name('libmd_environment.py').resolve())]=digest(Path(__file__).with_name('libmd_environment.py'))
    inputs[str(Path(configured_version_map.__file__).resolve())]=digest(Path(configured_version_map.__file__))
    inputs[str(Path(shared_link_script.__file__).resolve())]=digest(Path(shared_link_script.__file__))
    inputs[str(Path(configured_version_filter.__file__).resolve())]=digest(Path(configured_version_filter.__file__))
    inputs[str(Path(configured_static_objects.__file__).resolve())]=digest(Path(configured_static_objects.__file__))
    inputs[str(Path(compile_context.__file__).resolve())]=digest(Path(compile_context.__file__))
    inputs[str(Path(configured_syscalls.__file__).resolve())]=digest(Path(configured_syscalls.__file__))
    inputs[str(Path(configured_source_aliases.__file__).resolve())]=digest(Path(configured_source_aliases.__file__))
    inputs[str(Path(configured_rpc.__file__).resolve())]=digest(Path(configured_rpc.__file__))
    inputs[str(Path(configured_nls.__file__).resolve())]=digest(Path(configured_nls.__file__))
    inputs[str(Path(configured_programs.__file__).resolve())]=digest(Path(configured_programs.__file__))
    inputs[str(Path(configured_lexyacc.__file__).resolve())]=digest(Path(configured_lexyacc.__file__))
    inputs[str(Path(configured_variant_sources.__file__).resolve())]=digest(Path(configured_variant_sources.__file__))
    inputs[str(Path(configured_build_tools.__file__).resolve())]=digest(Path(configured_build_tools.__file__))
    tool_overrides=configured_build_tools.load(getattr(args,'tool_overrides',None),inputs)
    inputs[str(Path(configured_libmd.__file__).resolve())]=digest(Path(configured_libmd.__file__))
    records=[]
    def query(component,names,extra=()):
        # buildenv transports this command through Make and the environment.
        # Bound each request, rather than placing every per-source key in one
        # environment value. The budget includes shell quoting and -v switches;
        # output values are still checked for unambiguous one-line framing.
        batches=[];batch=[];size=0
        for name in names:
            cost=len(shlex.quote(name).encode())+4
            if cost>8192:raise ValueError('configuration key exceeds query transport budget')
            if batch and size+cost>8192:
                batches.append(batch);batch=[];size=0
            batch.append(name);size+=cost
        if batch:batches.append(batch)
        result={}
        for batch in batches:
            lines=env.query([v for name in batch for v in ('-v',name)],component=component,extra=extra).splitlines()
            if len(lines)!=len(batch):raise ValueError('multiline or ambiguous component values: '+str(component))
            result.update(zip(batch,lines))
        return result
    for component in components:
        base=query(component,VARIABLES,extra=tool_overrides)
        programs=configured_programs.selections(base)
        variants=[(None,base,tool_overrides)] if not programs else [
            (program,query(component,VARIABLES,extra=tool_overrides+selection),tool_overrides+selection)
            for program,selection in programs]
        for program,metadata,extra in variants:
            if (metadata['MACHINE'],metadata['MACHINE_ARCH'])!=('amd64','amd64'):raise ValueError('component target differs from world')
            variant_sources=configured_variant_sources.export(src,component,metadata,query,extra,inputs)
            extra_sources={r['name']:r for r in variant_sources}
            names=shlex.split(metadata['SRCS'])+list(extra_sources)
            perkeys=[('ACFLAGS.' if name.endswith('.S') else 'CXXFLAGS.' if name.endswith(('.cc','.cpp','.cxx','.C')) else 'CFLAGS.')+name for name in names]
            perkeys += [prefix+name for name in names for prefix in ('CFLAGS.','CXXFLAGS.','CWARNFLAGS.','CXXWARNFLAGS.')]
            perkeys=list(dict.fromkeys(perkeys))
            perkeys += [prefix+str(Path(name).with_suffix(suffix)) for name in names for suffix in ('.o','.pico','.pieo','.nossppico') for prefix in ('CFLAGS.','CWARNFLAGS.','ACFLAGS.')]
            per=query(component,perkeys,extra) if perkeys else {}
            static_objects=configured_static_objects.export(src,component,metadata,env,extra,inputs)
            closure={}
            for name in shlex.split(metadata['.MAKE.MAKEFILES']):
                p=Path(name);p=(p if p.is_absolute() else component/p).resolve(strict=True)
                if p!=Path('/dev/null'):closure[str(p)]=digest(p)
            inputs.update(closure)
            directories=[component]+[Path(p) if Path(p).is_absolute() else component/p for p in shlex.split(metadata['.PATH'])]
            syscall_generation=configured_syscalls.export(src,component,query,inputs)
            syscall_names={v['name'] for v in syscall_generation['outputs']} if syscall_generation else set()
            if not syscall_names<=set(names):raise ValueError('syscall output absent from configured source inventory')
            aliases=configured_source_aliases.export(src,component,names,query,extra,inputs)
            nls_generation=configured_nls.export(src,component,query,extra,inputs)
            rpc_generation=configured_rpc.export(src,component,env,query,extra,inputs)
            rpc_names={r['name'] for r in rpc_generation['outputs']} if rpc_generation else set()
            if not rpc_names<=set(names):raise ValueError('RPC output absent from configured sources')
            lexyacc_generation=configured_lexyacc.export(src,component,env,query,extra,inputs)
            lexyacc_names={n for g in lexyacc_generation['generators'] for n in (g['name'],g['header']) if n} if lexyacc_generation else set()
            if not lexyacc_names<=set(names):raise ValueError('lexer/parser output absent from configured sources')
            digest_generation=configured_libmd.export(src,component,query,extra,inputs)
            digest_names={r['name'] for r in digest_generation['outputs']} if digest_generation else set()
            digest_headers={r['name'] for r in digest_generation['headers']} if digest_generation else set()
            if not (digest_names|digest_headers)<=set(names):raise ValueError('digest generation outputs absent from SRCS')
            sources=[]
            for name in names:
                resolved=None
                for directory in directories:
                    p=(directory/name).resolve()
                    if p.is_file() and p.is_relative_to(src):resolved=p;break
                if name in extra_sources and resolved!=src/extra_sources[name]['path']:
                    raise ValueError('extra variant origin differs from Make source search: '+name)
                if name in digest_names | digest_headers:
                    if resolved is not None or name in aliases or name in syscall_names or name in rpc_names or name in lexyacc_names:raise ValueError('digest output conflicts with another source')
                    sources.append(dict(name=name,resolution='generated-digest' if name in digest_names else 'digest-header'))
                elif name in lexyacc_names:
                    if resolved is not None or name in aliases or name in syscall_names or name in rpc_names:raise ValueError('lexer/parser output conflicts with another input')
                    sources.append(dict(name=name,resolution='generated-lexyacc'))
                elif name in rpc_names:
                    if resolved is not None or name in aliases or name in syscall_names:raise ValueError('RPC output conflicts with another input')
                    sources.append(dict(name=name,resolution='generated-rpc'))
                elif name in aliases:
                    if resolved is not None or name in syscall_names:raise ValueError('source alias conflicts with another input: '+name)
                    sources.append(aliases[name])
                elif name in syscall_names:
                    if resolved is not None:raise ValueError('generated syscall conflicts with source-tree file')
                    sources.append({'name':name,'resolution':'generated-syscall'})
                elif resolved is None:
                    sources.append({'name':name,'resolution':'requires-declared-generation'})
                else:
                    sha=digest(resolved);inputs[str(resolved)]=sha
                    sources.append({'name':name,'resolution':'source','path':str(resolved.relative_to(src)),'sha256':sha})
            textual_keys=['TEXTUAL_SRCS.'+name for name in names]
            textual_values=query(component,textual_keys,extra) if textual_keys else {}
            for source in sources:
                textual=[]
                for value in shlex.split(textual_values['TEXTUAL_SRCS.'+source['name']]):
                    path=Path(value)
                    if not path.is_absolute():raise ValueError('textual source requires explicit source path')
                    path=path.resolve(strict=True)
                    if not path.is_relative_to(src) or not path.is_file():raise ValueError('textual input outside source tree')
                    sha=digest(path);inputs[str(path)]=sha
                    textual.append(dict(path=str(path.relative_to(src)),sha256=sha))
                source['textual_inputs']=textual
            if textual_keys and query(component,textual_keys,extra)!=textual_values:
                raise ValueError('textual source dependencies changed during export')
            if metadata['LIB'] or metadata['PROG'] or metadata['SHLIB_NAME']:
                object_sets={variant:set(shlex.split(metadata[key])) for variant,key in
                    (('regular','OBJS'),('pic','SOBJS'),('pie','PIEOBJS'),('nossp_pic','NOSSPSOBJS'))}
                if not metadata['LIB'] and not metadata['PROG']:
                    object_sets={variant:objects if variant=='pic' else set() for variant,objects in object_sets.items()}
                elif not metadata['LIB']:
                    object_sets={variant:set(shlex.split(metadata['OBJS'])) if variant in ('regular','pie') else set()
                                 for variant in object_sets}
                selected_sources=[source for source in sources if source['resolution'] in ('source','source-alias','generated-syscall','generated-rpc','generated-lexyacc','generated-digest') and Path(source['name']).suffix in ('.c','.cc','.cpp','.cxx','.C','.S')]
                def export_context(source):
                    language='assembler-with-cpp' if source['name'].endswith('.S') else 'c' if source['name'].endswith('.c') else 'c++'
                    contexts={}
                    for variant,suffix in (('regular','.o'),('pic','.pico'),('pie','.pieo'),('nossp_pic','.nossppico')):
                        target=str(Path(source['name']).with_suffix(suffix))
                        if target in object_sets[variant]:
                            contexts[variant]=compile_context.capture(env,component,str(src/source['path']) if source['resolution']=='source' else source['name'],target,language,extra=extra)
                    if not contexts:raise ValueError('source lacks any configured object variant: '+source['name'])
                    return contexts
                # Only independent read-only queries run concurrently. Ordered map
                # results preserve source/variant ordering in the native graph.
                with ThreadPoolExecutor(max_workers=jobs) as executor:
                    contexts=list(executor.map(export_context,selected_sources))
                for source,context in zip(selected_sources,contexts,strict=True):
                    source['compile_contexts']=context
            dtrace_providers=[]
            for provider in shlex.split(metadata['DTRACE_PROVIDERS']):
                key='DTRACE_PROVIDER_HEADER.'+provider
                header=query(component,[key],extra)[key]
                if not header or Path(header).name!=header:raise ValueError('unsupported DTrace provider header')
                resolved=None
                for directory in directories:
                    p=(directory/provider).resolve()
                    if p.is_file() and p.is_relative_to(src):resolved=p;break
                if resolved is None:raise ValueError('DTrace provider requires declared generation: '+provider)
                inputs[str(resolved)]=digest(resolved)
                dtrace_providers.append({'name':provider,'path':str(resolved.relative_to(src)),
                    'sha256':inputs[str(resolved)],'header':header})
            dtrace_configuration=None
            if dtrace_providers:
                selected=query(component,['PATH','.OBJDIR'],extra)
                command=shlex.split(metadata['DTRACE'])
                if len(command)!=1:
                    raise ValueError('DTrace command needs explicit executable mapping')
                if '/' in command[0] and not Path(command[0]).is_absolute():
                    raise ValueError('relative DTrace executable needs explicit mapping')
                executable=shutil.which(command[0],path=selected['PATH'])
                if executable is None:raise ValueError('configured DTrace executable not found')
                executable=Path(executable).resolve(strict=True)
                sysflags=shlex.split(metadata['_DTRACE_SYSROOT_FLAG'])
                if len(sysflags)!=2 or sysflags[0]!='-x' or not sysflags[1].startswith('syslibdir='):
                    raise ValueError('DTrace requires an explicit target syslibdir')
                directory=Path(sysflags[1].split('=',1)[1])
                if not directory.is_absolute():raise ValueError('absolute DTrace syslibdir required')
                drti=(directory/'drti.o').resolve(strict=True)
                anchor=env.query(['-V','${DTRACE_STATIC_ANCHOR:Dyes:Uno}'],component=component,extra=extra).strip()
                if anchor not in ('yes','no'):raise ValueError('ambiguous DTrace anchor state')
                for path in (executable,drti):inputs[str(path)]=digest(path)
                dtrace_configuration={'executable':{'path':str(executable),'sha256':inputs[str(executable)]},
                    'flags':shlex.split(metadata['DTRACEFLAGS']),
                    'drti':{'path':str(drti),'sha256':inputs[str(drti)]},
                    'generated_include_directory':selected['.OBJDIR'],
                    'static_anchor':anchor=='yes'}
            library_dependencies=[]
            framework_keys=['TEST_FRAMEWORK_LIBS.'+program,'TEST_INTERFACE.'+program,'_TEST_METADATA.'+program,'TESTS_ENV','_TESTS_DEFAULT_LD_LIBRARY_PATH','KYUAFILE','TESTSUITE'] if program else []
            framework=query(component,framework_keys,extra) if framework_keys else {}
            framework_names=shlex.split(framework.get('TEST_FRAMEWORK_LIBS.'+str(program),''))
            dependency_names=framework_names+shlex.split(metadata['LIBADD'])
            if len(dependency_names)!=len(set(dependency_names)):
                raise ValueError('duplicate framework/component library dependency')
            dependency_keys=[key for name in dependency_names for key in
                ('LIB'+name.upper()+'SRCDIR','LDADD_'+name,'DPADD_'+name)]
            dependency_values=query(component,dependency_keys,extra) if dependency_keys else {}
            for name in dependency_names:
                directory=Path(dependency_values['LIB'+name.upper()+'SRCDIR'])
                if not directory.is_absolute():raise ValueError('dependency lacks explicit source directory: '+name)
                directory=directory.resolve(strict=True)
                if not directory.is_relative_to(src) or not (directory/'Makefile').is_file():
                    raise ValueError('dependency source outside maintained tree: '+name)
                library_dependencies.append({'name':name,'component':str(directory.relative_to(src)),
                    'ldadd':shlex.split(dependency_values['LDADD_'+name]),
                    'dpadd':shlex.split(dependency_values['DPADD_'+name])})
            fidl_bindings=[]
            fidl_configuration=None
            if shlex.split(metadata['FIDL_BINDINGS']):
                fidl_environment=query(component,['PATH','.OBJDIR'],extra)
                execution_tools={}
                for role,key in (('compiler','FIDLC'),('python','PYTHON')):
                    command=shlex.split(metadata[key])
                    if len(command)!=1 or ('/' in command[0] and not Path(command[0]).is_absolute()):
                        raise ValueError('FIDL '+key+' requires an explicit executable without embedded arguments')
                    executable=shutil.which(command[0],path=fidl_environment['PATH'])
                    if executable is None:raise ValueError('configured FIDL executable not found: '+key)
                    executable=Path(executable).resolve(strict=True)
                    inputs[str(executable)]=digest(executable)
                    execution_tools[role]={'path':str(executable),'sha256':inputs[str(executable)]}
                object_directory=Path(fidl_environment['.OBJDIR'])
                if not object_directory.is_absolute() or not object_directory.is_relative_to(args.objtop.resolve()):
                    raise ValueError('FIDL object directory outside selected world')
                fidl_configuration={'execution_tools':execution_tools,'object_directory':str(object_directory)}
            for binding in shlex.split(metadata['FIDL_BINDINGS']):
                keys=[prefix+'.'+binding for prefix in ('FIDL_LIBRARY','FIDL_FLAGS','FIDLGEN','_FIDLGEN_INPUTS','FIDLGEN_SRCS','FIDLGEN_HEADERS')]
                values=query(component,keys,extra)
                def fidl_input(name):
                    p=Path(name)
                    p=(p if p.is_absolute() else component/p).resolve(strict=True)
                    if not p.is_file() or not p.is_relative_to(src):raise ValueError('FIDL input outside maintained source: '+name)
                    inputs[str(p)]=digest(p)
                    return {'path':str(p.relative_to(src)),'sha256':inputs[str(p)]}
                schemas=[fidl_input(p) for p in shlex.split(values['_FIDLGEN_INPUTS.'+binding])]
                tools=[fidl_input(p) for p in shlex.split(metadata['_FIDLGEN_TOOLS'])]
                generated_sources=shlex.split(values['FIDLGEN_SRCS.'+binding])
                generated_headers=shlex.split(values['FIDLGEN_HEADERS.'+binding])
                outputs=generated_sources+generated_headers
                if not schemas or not tools or not generated_sources or not generated_headers or len(outputs)!=len(set(outputs)):
                    raise ValueError('incomplete or duplicate FIDL input/output inventory')
                if any(Path(p).is_absolute() or '..' in Path(p).parts for p in outputs):raise ValueError('FIDL output escapes object tree')
                configured_root=Path(values['FIDLGEN.'+binding])
                if not configured_root.is_absolute() or '..' in configured_root.parts:
                    raise ValueError('FIDL generation root must be an absolute normalized path')
                generated_root=configured_root.resolve()
                if not generated_root.is_absolute() or generated_root==object_directory or not generated_root.is_relative_to(object_directory):
                    raise ValueError('FIDL generation root must be below component object directory')
                relative_outputs=[]
                for output in outputs:
                    path=object_directory/output
                    if not path.is_relative_to(generated_root):raise ValueError('FIDL output outside configured generation root')
                    relative_outputs.append(str(path.relative_to(generated_root)))
                generator=fidl_input(str(Path(metadata['_FIDLGEN_DIR'])/'fidlgen-build.py'))
                template_directory=Path(metadata['_FIDLGEN_TEMPLATES']).resolve(strict=True)
                if not template_directory.is_relative_to(src):raise ValueError('FIDL template directory outside source')
                if generator not in tools:raise ValueError('FIDL generator missing from declared tool closure')
                fidl_bindings.append({'generator':generator,'template_directory':str(template_directory.relative_to(src)),
                    'generated_root':str(generated_root),'relative_sources':relative_outputs[:len(generated_sources)],
                    'relative_headers':relative_outputs[len(generated_sources):],'name':binding,'library':values['FIDL_LIBRARY.'+binding],
                    'flags':shlex.split(values['FIDL_FLAGS.'+binding]),'available':metadata['FIDL_AVAILABLE'],
                    'schemas':schemas,'generator_inputs':tools,'sources':generated_sources,'headers':generated_headers})
                if query(component,keys,extra)!=values:raise ValueError('FIDL binding configuration changed')
            link_script=shared_link_script.export(src,component,metadata,inputs)
            version_filter=configured_version_filter.export(src,component,metadata,env,extra,inputs)
            version_map=None
            if metadata['VERSION_MAP'] and not metadata['SYMBOL_MAPS'] and version_filter is None:
                p=Path(metadata['VERSION_MAP'])
                p=(p if p.is_absolute() else component/p).resolve(strict=True)
                if not p.is_relative_to(src):raise ValueError('version map outside maintained source')
                inputs[str(p)]=digest(p)
                version_map={'path':str(p.relative_to(src)),'sha256':inputs[str(p)]}
            generated_version_map=configured_version_map.export(src,component,metadata,env,extra,inputs)
            generators=[]
            outputs=[('PC',v) for v in shlex.split(metadata['PCFILES'])]+[('CONF',v) for v in shlex.split(metadata['CONF_GENERATED'])]
            if len({v for _,v in outputs})!=len(outputs):raise ValueError('duplicate template output')
            for prefix,output in outputs:
                if Path(output).name!=output:raise ValueError('generated output must be a basename')
                keys=[prefix+'_'+kind+'.'+output for kind in ('GENERATOR','TEMPLATE','TOOLS','ARGS','DEPENDENCIES')]
                values=query(component,keys,extra)
                if not all(values[k] for k in keys[:4]):raise ValueError('template output lacks explicit generation metadata: '+output)
                files=[]
                for key in keys[:2]:
                    p=Path(values[key]).resolve(strict=True)
                    if not p.is_relative_to(src):raise ValueError('generator input outside source')
                    inputs[str(p)]=digest(p);files.append(str(p.relative_to(src)))
                dependencies=[]
                for value in shlex.split(values[keys[4]]):
                    p=Path(value).resolve(strict=True)
                    if not p.is_relative_to(src):raise ValueError('generator dependency outside source')
                    inputs[str(p)]=digest(p);dependencies.append(str(p.relative_to(src)))
                generators.append({'dependencies':dependencies,'output':output,'script':files[0],'template':files[1],'tools':shlex.split(values[keys[2]]),'arguments':shlex.split(values[keys[3]])})
            # Requery all fields to catch changes between configuration and closure hashing.
            if framework_keys and query(component,framework_keys,extra)!=framework:raise ValueError('test framework changed during export')
            if query(component,VARIABLES,extra)!=metadata:raise ValueError('component configuration changed during export')
            if dtrace_configuration is not None:
                if query(component,['PATH','.OBJDIR'],extra)!=selected:
                    raise ValueError('DTrace tool search path or object directory changed')
                if env.query(['-V','${DTRACE_STATIC_ANCHOR:Dyes:Uno}'],component=component,extra=extra).strip()!=anchor:
                    raise ValueError('DTrace anchor configuration changed')
            if fidl_configuration is not None and query(component,['PATH','.OBJDIR'],extra)!=fidl_environment:
                raise ValueError('FIDL tool search path or object directory changed')
            if dependency_keys and query(component,dependency_keys,extra)!=dependency_values:
                raise ValueError('library dependency mapping changed during export')
            records.append({'component':str(component.relative_to(src)),'program_override':program,'metadata':metadata,'sources':sources,'syscall_generation':syscall_generation,'rpc_generation':rpc_generation,'nls_generation':nls_generation,'lexyacc_generation':lexyacc_generation,'digest_generation':digest_generation,'static_objects':static_objects,'variant_sources':variant_sources,'dtrace_providers':dtrace_providers,'dtrace_configuration':dtrace_configuration,'fidl_bindings':fidl_bindings,'fidl_configuration':fidl_configuration,'test_policy':dict(metadata=framework.get('_TEST_METADATA.'+str(program),''),environment=framework.get('TESTS_ENV',''),default_library_paths=framework.get('_TESTS_DEFAULT_LD_LIBRARY_PATH',''),kyuafile=framework.get('KYUAFILE',''),suite=framework.get('TESTSUITE','')) if program else None,'framework_library_names':framework_names,'test_interface':framework.get('TEST_INTERFACE.'+str(program),''),'library_dependencies':library_dependencies,'per_file_flags':per,'generators':generators,'shared_link_script':link_script,'version_filter':version_filter,'version_map':version_map,'generated_version_map':generated_version_map,'make_include_closure':closure})
    env.verify()
    for p,h in inputs.items():
        if digest(Path(p))!=h:raise ValueError('configuration input changed: '+p)
    result={'format':1,'status':'configured','scope':'selected component metadata only; not a build or complete package inventory','components':records,'build_environment':env.receipt(),'input_sha256':inputs,'elapsed_seconds':time.monotonic()-start,'configuration_jobs':jobs,'execution_tool_overrides':tool_overrides,'limitations':['Selection is explicit; world/package recursion coverage is not yet derived.','Generated sources require explicit graph declarations.','Compiler/header closure and native compilation are not qualified by this export.']}
    out.mkdir(parents=True)
    (out/'components.json').write_text(json.dumps(result,indent=2)+'\n')
    print(out/'components.json')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('src','objtop','profile','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--make',type=Path,default=Path('/usr/bin/make'))
    p.add_argument('--tool-overrides',type=Path,help='format-1 JSON with explicit Make executable selections')
    p.add_argument('--component',action='append',required=True)
    p.add_argument('--jobs',type=int,default=os.cpu_count() or 1)
    export(p.parse_args())
