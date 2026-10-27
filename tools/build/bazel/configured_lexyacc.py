# SPDX-License-Identifier: BSD-2-Clause
"""Export lexer/parser metadata from bsd.dep.mk and emit declared generators."""
from pathlib import Path
import shlex,shutil
from libmd_environment import digest


def export(src,component,env,query,extra,inputs):
    keys=['LEX_OUTPUTS','YACC_OUTPUTS','LEX','LEX_M4','YACC','PATH','.PATH','.OBJDIR']
    base=query(component,keys,extra)
    lex=shlex.split(base['LEX_OUTPUTS']);yacc=shlex.split(base['YACC_OUTPUTS'])
    if not lex and not yacc:return None
    names=lex+yacc
    if len(names)!=len(set(names)) or any(Path(n).name!=n or not n.endswith('.c') for n in names):
        raise ValueError('unique lexer/parser C output basenames required')
    fields=[prefix+n for n in lex for prefix in ('LEX_SOURCE.','LEX_FLAGS.')]
    fields += [prefix+n for n in yacc for prefix in ('YACC_SOURCE.','YACC_FLAGS.','YACC_HEADER.','YACC_STYLE.')]
    values=query(component,fields,extra);tools={};records=[];all_outputs=set(names)
    for role,key in ([('lex','LEX'),('m4','LEX_M4')] if lex else [])+([('yacc','YACC')] if yacc else []):
        command=[base[key]] if role=='m4' else shlex.split(base[key])
        if len(command)!=1:raise ValueError('generator requires one selected executable: '+role)
        executable=shutil.which(command[0],path=base['PATH'])
        if executable is None:raise ValueError('configured generator not found: '+role)
        path=Path(executable).resolve(strict=True);sha=digest(path);inputs[str(path)]=sha;tools[role]=dict(path=str(path),sha256=sha)
    directories=[component]+[Path(p) if Path(p).is_absolute() else component/p for p in shlex.split(base['.PATH'])]
    for name in names:
        kind='lex' if name in lex else 'yacc';prefix=kind.upper();source_name=values[prefix+'_SOURCE.'+name]
        if Path(source_name).name!=source_name or Path(source_name).suffix!=('.l' if kind=='lex' else '.y'):
            raise ValueError('generator input requires a grammar basename')
        source=next(((d/source_name).resolve() for d in directories if (d/source_name).is_file() and (d/source_name).resolve().is_relative_to(src)),None)
        if source is None:raise ValueError('grammar origin outside maintained sources or missing')
        flags=shlex.split(values[prefix+'_FLAGS.'+name]);header=''
        if any(f in ('-v','-b','-o','-t') or f.startswith(('--header-file','-S')) for f in flags):
            raise ValueError('generator flags require additional input/output support')
        if kind=='yacc':
            if values['YACC_STYLE.'+name]!='named':raise ValueError('traditional yacc output mode requires explicit support')
            header=values['YACC_HEADER.'+name]
            if bool(header)!=('-d' in flags) or (header and header!=str(Path(name).with_suffix('.h'))):
                raise ValueError('parser header differs from configured output mode')
            if header:
                if header in all_outputs:raise ValueError('generator output collision')
                all_outputs.add(header)
        sha=digest(source);inputs[str(source)]=sha
        records.append(dict(kind=kind,name=name,header=header,source=dict(path=str(source.relative_to(src)),sha256=sha),flags=flags))
    if query(component,keys,extra)!=base or query(component,fields,extra)!=values:raise ValueError('generator metadata changed during export')
    return dict(generators=records,tools=tools,generated_include_directory=base['.OBJDIR'])


def emit(component,receipt,src,copy,rule):
    record=component.get('lexyacc_generation')
    if not record:return {},[]
    for role,tool in record['tools'].items():
        if receipt['tool_origins'].get('extra_'+role)!=tool['path'] or receipt['inputs'].get(tool['path'])!=tool['sha256']:
            raise ValueError('configured generator differs from staged SDK: '+role)
    name=component['metadata']['LIB'] or component['metadata']['PROG'];outputs={};headers=[]
    for row in record['generators']:
        path=src/row['source']['path']
        if not path.resolve().is_relative_to(src) or digest(path)!=row['source']['sha256']:raise ValueError('grammar input changed')
        output='generated/'+name+'/'+row['name'];outputs[row['name']]=output
        attrs=dict(name=name+'_generate_'+row['name'],kind=row['kind'],source=copy(path),output=output,flags=row['flags'],generator='//toolchain:extra_'+row['kind'],runtime=['//toolchain:extra_'+row['kind']+'_runtime'])
        if row['header']:
            attrs['header']='generated/'+name+'/'+row['header'];outputs[row['header']]=attrs['header'];headers.append(attrs['header'])
        if row['kind']=='lex':attrs.update(m4='//toolchain:extra_m4',runtime=attrs['runtime']+['//toolchain:extra_m4_runtime'])
        rule('bsd_lexyacc',**attrs)
    return outputs,headers
