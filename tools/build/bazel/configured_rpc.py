# SPDX-License-Identifier: BSD-2-Clause
"""Capture and emit RPC outputs declared by maintained Make recipes."""
from pathlib import Path
import shlex
import shutil
from libmd_environment import digest
from configured_version_map import cpp_flags


def export(src,component,env,query,extra,inputs):
    keys=['RPCGEN_OUTPUTS','RPCGEN_TOOL','RPCGEN_FLAGS','RPCGEN','CPP','PATH','.OBJDIR']
    base=query(component,keys,extra)
    names=shlex.split(base['RPCGEN_OUTPUTS'])
    if not names:return None
    if len(names)!=len(set(names)) or any(Path(n).name!=n or Path(n).suffix not in ('.h','.c') for n in names):
        raise ValueError('unique RPC output basenames required')
    tool=shlex.split(base['RPCGEN_TOOL']);flags=shlex.split(base['RPCGEN_FLAGS']);cpp=shlex.split(base['CPP'])
    if len(tool)!=1 or flags!=['-C'] or not cpp:
        raise ValueError('RPC invocation requires explicit supported tool/flag policy')
    if shlex.split(base['RPCGEN'])!=['RPCGEN_CPP='+base['CPP'],*tool,*flags]:
        raise ValueError('RPC recipe differs from exported invocation')
    def executable(name):
        path=shutil.which(name,path=base['PATH'])
        if path is None:raise ValueError('configured RPC tool not found: '+name)
        path=Path(path).resolve(strict=True);sha=digest(path);inputs[str(path)]=sha
        return dict(path=str(path),sha256=sha)
    generator=executable(tool[0]);preprocessor=executable(cpp[0])
    if preprocessor['sha256']!=digest(env.compiler):
        raise ValueError('RPC preprocessor differs from selected staged Clang')
    fields=[prefix+n for n in names for prefix in ('RPCGEN_SOURCE.','RPCGEN_MODE.','RPCGEN_DEPS.')]
    values=query(component,fields,extra);outputs=[]
    for name in names:
        source=Path(values['RPCGEN_SOURCE.'+name])
        if not source.is_absolute():raise ValueError('RPC schema requires an absolute source origin')
        source=source.resolve(strict=True)
        if not source.is_relative_to(src) or not source.is_file() or source.suffix!='.x':
            raise ValueError('RPC schema must be a maintained .x source')
        mode=values['RPCGEN_MODE.'+name];deps=shlex.split(values['RPCGEN_DEPS.'+name])
        if mode not in ('-h','-l','-c') or (mode=='-h')!=name.endswith('.h'):
            raise ValueError('RPC mode/output mismatch')
        if len(deps)!=len(set(deps)) or name in deps or any(d not in names for d in deps):
            raise ValueError('RPC dependencies must name other declared outputs')
        sha=digest(source);inputs[str(source)]=sha
        outputs.append(dict(name=name,source=dict(path=str(source.relative_to(src)),sha256=sha),mode=mode,dependencies=deps))
    if query(component,keys,extra)!=base or query(component,fields,extra)!=values:
        raise ValueError('RPC generation policy changed during export')
    return dict(generated_include_directory=base['.OBJDIR'],outputs=outputs,flags=flags,tool=generator,preprocessor=preprocessor,cpp_command=cpp,compiler_resource=env.resource)


def emit(component,receipt,src,objtop,copy,rule):
    record=component.get('rpc_generation')
    if not record:return {},[]
    for role,selected in [('extra_rpcgen',record['tool']),('cpp',record['preprocessor'])]:
        if receipt['tool_origins'].get(role)!=selected['path'] or receipt['inputs'].get(selected['path'])!=selected['sha256']:
            raise ValueError('configured RPC tool differs from staged SDK: '+role)
    name=component['metadata']['LIB'] or component['metadata']['PROG']
    outputs={r['name']:'generated/'+name+'/'+r['name'] for r in record['outputs']}
    flags=cpp_flags(record['cpp_command'],objtop,record['compiler_resource'])
    for row in record['outputs']:
        origin=src/row['source']['path']
        if not origin.resolve().is_relative_to(src) or digest(origin)!=row['source']['sha256']:
            raise ValueError('RPC schema changed or escaped source tree')
        rule('bsd_rpcgen',name=name+'_rpc_'+row['name'],source=copy(origin),output=outputs[row['name']],mode=row['mode'],flags=record['flags'],cpp_flags=flags,
             dependencies=[outputs[d] for d in row['dependencies']],rpcgen='//toolchain:extra_rpcgen',cpp='//toolchain:bin/cpp',
             compiler_inputs='//toolchain:compile_inputs',runtime=['//toolchain:extra_rpcgen_runtime','//toolchain:cpp_runtime'])
    return outputs,[output for name,output in outputs.items() if name.endswith('.h')]
