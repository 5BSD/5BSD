# SPDX-License-Identifier: BSD-2-Clause
"""Shared libmd digest-source and header-mapping metadata from maintained Make."""
from pathlib import Path
import re
import shlex
import shutil
from libmd_environment import digest


def export(src, component, query, extra, inputs):
    keys=['LIBMD_GENHL_SRCS','LIBMD_GENHL_SCRIPT','LIBMD_GENHL_TEMPLATE',
          'LIBMD_HEADER_ALIASES','LIBMD_GEN_SH','LIBMD_GEN_SED','LIBMD_GEN_MV','LIBMD_GEN_RM','PATH']
    base=query(component,keys,extra)
    names=shlex.split(base['LIBMD_GENHL_SRCS'])
    aliases=shlex.split(base['LIBMD_HEADER_ALIASES'])
    if not names and not aliases:return None
    if not names or len(names)!=len(set(names)) or any(Path(n).name!=n or not n.endswith('.c') for n in names):
        raise ValueError('unique digest generator C basenames required')
    if len(aliases)!=len(set(aliases)) or any(Path(n).is_absolute() or '..' in Path(n).parts or str(Path(n))!=n or not n.endswith('.h') for n in aliases):
        raise ValueError('unique relative header mapping names required')
    def source(value):
        path=Path(value)
        if not path.is_absolute():raise ValueError('generator source must be absolute')
        path=path.resolve(strict=True)
        if not path.is_relative_to(src) or not path.is_file():raise ValueError('generator source outside source tree')
        sha=digest(path);inputs[str(path)]=sha
        return dict(path=str(path.relative_to(src)),sha256=sha)
    fields=['LIBMD_GENHL_ARGS.'+n for n in names]+['LIBMD_HEADER_SOURCE.'+n for n in aliases]
    values=query(component,fields,extra)
    outputs=[]
    for name in names:
        args=shlex.split(values['LIBMD_GENHL_ARGS.'+name])
        if (len(args)!=4 or not re.fullmatch('[0-9]+',args[0]) or
            any(not re.fullmatch('[A-Za-z0-9_]+',arg) for arg in args[1:3]) or
            (args[3]!='-' and not re.fullmatch('[A-Za-z0-9_]+',args[3]))):
            raise ValueError('unsupported digest generator arguments: '+name)
        outputs.append(dict(name=name,arguments=args))
    headers=[dict(name=n,source=source(values['LIBMD_HEADER_SOURCE.'+n])) for n in aliases]
    tools={}
    for role in ('sh','sed','mv','rm'):
        words=shlex.split(base['LIBMD_GEN_'+role.upper()])
        if len(words)!=1:raise ValueError('digest generator requires a single executable: '+role)
        found=shutil.which(words[0],path=base['PATH'])
        if found is None:raise ValueError('digest generator tool not found: '+role)
        tool=Path(found).resolve(strict=True);sha=digest(tool);inputs[str(tool)]=sha
        tools[role]=dict(path=str(tool),sha256=sha)
    result=dict(script=source(base['LIBMD_GENHL_SCRIPT']),template=source(base['LIBMD_GENHL_TEMPLATE']),outputs=outputs,headers=headers,tools=tools)
    if query(component,keys,extra)!=base or query(component,fields,extra)!=values:
        raise ValueError('digest generator configuration changed during export')
    return result


def emit(component, receipt, src, out, copy, rule, inputs):
    record=component.get('digest_generation')
    if not record:return {},[]
    name=component['metadata']['LIB'] or component['metadata']['PROG']
    def checked(row):
        origin=src/row['path']
        if not origin.resolve().is_relative_to(src) or digest(origin)!=row['sha256']:
            raise ValueError('digest generator source changed')
        return origin
    for role, selected in record['tools'].items():
        if receipt['tool_origins'].get(role)!=selected['path'] or receipt['inputs'].get(selected['path'])!=selected['sha256']:
            raise ValueError('digest generator tool differs from staged SDK: '+role)
    script=copy(checked(record['script']));template=copy(checked(record['template']))
    outputs={}
    for row in record['outputs']:
        output='generated/'+name+'/'+row['name'];outputs[row['name']]=output
        rule('libmd_generated',name=name+'_digest_'+row['name'],output=output,kind='high_level',
             script=script,template=template,arguments=row['arguments'],
             shell='//toolchain:sh',sed='//toolchain:sed',mv='//toolchain:mv',rm='//toolchain:rm',
             execution_runtime=['//toolchain:'+role+'_runtime' for role in ('sh','sed','mv','rm')])
    # These aliases do not transform bytes: snapshot the declared origin at the
    # component's logical include path, as the standalone libmd exporter does.
    headers=[]
    for row in record['headers']:
        origin=checked(row['source']);relative=Path('sources')/component['component']/row['name']
        dest=out/relative
        if not dest.resolve().is_relative_to(out):raise ValueError('header mapping escaped workspace')
        if dest.exists():raise ValueError('header mapping collides with existing source')
        dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(origin,dest)
        inputs[str(origin)]=digest(origin)
        if digest(dest)!=row['source']['sha256']:raise ValueError('header mapping snapshot differs')
        headers.append('//:'+str(relative))
    return outputs,headers
