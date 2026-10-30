#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify actual native symbol-map actions against Make and incremental changes.

Requires a fresh disposable component workspace; leaves logs for every case.
"""
import argparse
import collections
import json
import os
from pathlib import Path
import shlex
import subprocess
from libmd_environment import BuildEnvironment,digest
from configured_version_map import cpp_flags


def actions(path):
    text=path.read_text();decoder=json.JSONDecoder();offset=0;result=[]
    while offset<len(text):
        while offset<len(text) and text[offset].isspace():offset+=1
        if offset==len(text):break
        record,offset=decoder.raw_decode(text,offset);result.append(record)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('src','plan','workspace','build-command','java-home','output'):
        parser.add_argument('--'+key,type=Path,required=True)
    args=parser.parse_args();src=args.src.resolve(strict=True);workspace=args.workspace.resolve(strict=True)
    out=args.output.resolve();plan=json.loads(args.plan.read_text())
    if out.exists() or not out.is_relative_to('/usr/obj') or out==Path('/usr/obj') or workspace.is_relative_to(out):raise ValueError('fresh output under /usr/obj required')
    if not workspace.is_relative_to('/usr/obj') or (workspace/'bazel-bin').exists():raise ValueError('fresh disposable component workspace required')
    components=[c for c in plan['components'] if c.get('generated_version_map')]
    if len(components)!=1:raise ValueError('one generated-map component required')
    component=components[0];record=component['generated_version_map'];obj=Path(plan['build_environment']['objtop'])
    env=BuildEnvironment(src,obj,Path(plan['build_environment']['profile']),Path('/usr/bin/make'))
    for p,h in plan['input_sha256'].items():
        if digest(Path(p))!=h:raise ValueError('plan input changed: '+p)
    argv=json.loads(args.build_command.read_text())['argv'];index=next(i for i,x in enumerate(argv) if x in ('build','test'))
    startup=[x for x in argv[:index] if not x.startswith('--output_user_root=')]
    startup+=['--output_user_root='+str(workspace.parent/'bazel-user-root')]
    options=[x for x in argv[index+1:] if not x.startswith(('--build_event_json_file=','--execution_log_json_file=','//'))]
    if not any(x.startswith('--jobs=') for x in options):raise ValueError('explicit build parallelism required')
    runenv={'PATH':'/bin:/usr/bin:/usr/local/bin','HOME':os.environ['HOME'],'LC_ALL':'C','JAVA_HOME':str(args.java_home.resolve(strict=True)),'BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN':'1'}
    out.mkdir();fixtures=workspace/'version-map-fixtures';fixtures.mkdir()
    first=fixtures/'first.map';second=fixtures/'second.map';versions=fixtures/'Versions.def'
    first_text='#ifndef QUALIFY_FEATURE\n#error missing configured flag\n#endif\n#define QUALIFY_SYMBOL qualified_first\n'
    second_text='#ifndef QUALIFY_SYMBOL\n#error symbol map ordering lost\n#endif\nQUALIFY_1.0 {\n QUALIFY_SYMBOL;\n#ifdef QUALIFY_SECOND\n qualified_second;\n#endif\n};\n'
    first.write_text(first_text);second.write_text(second_text);versions.write_text('QUALIFY_1.0 {\n};\n')
    build=workspace/'BUILD.bazel';original=build.read_text();cases=[]
    generator='sources/'+record['generator']['path']
    if digest(workspace/generator)!=record['generator']['sha256']:raise ValueError('generator snapshot differs')
    baseflags=['-DQUALIFY_FEATURE=1','-DQUALIFY_SECOND=1']
    def configure(flags,reverse=False):
        ordered=[str(p.relative_to(workspace)) for p in (first,second)]
        if reverse:ordered.reverse()
        attrs=dict(name='version_map_qualification',symbol_maps=ordered,
                   versions=str(versions.relative_to(workspace)),generator=generator,
                   cpp_flags=cpp_flags(record['cpp_command'],obj,record['compiler_resource']),copts=flags,
                   compiler='//toolchain:bin/clang',compiler_inputs='//toolchain:compile_inputs',
                   cat='//toolchain:cat',cat_runtime='//toolchain:cat_runtime',awk='//toolchain:awk',
                   awk_runtime='//toolchain:awk_runtime',redirect='//toolchain:stdout_redirect')
        build.write_text(original+'\nbsd_configured_version_map('+', '.join(k+'='+repr(v) for k,v in attrs.items())+')\n')
    def run(name,success=True,reason=None):
        prefix=out/name
        command=[*startup,'build',*options,'--build_event_json_file='+str(prefix)+'.events.json','--execution_log_json_file='+str(prefix)+'.execution.json','//...']
        (out/(name+'.BUILD.bazel')).write_text(build.read_text())
        with (out/(name+'.stdout')).open('w') as stdout,(out/(name+'.stderr')).open('w') as stderr:
            done=subprocess.run(['/usr/bin/time','-l',*command],cwd=workspace,env=runenv,stdout=stdout,stderr=stderr)
        log=(out/(name+'.stderr')).read_text()
        item={'case':name,'argv':command,'exit_status':done.returncode}
        cases.append(item)
        (out/'commands.json').write_text(json.dumps(cases,indent=2)+'\n')
        if (done.returncode==0)!=success:raise AssertionError(name+': unexpected build status')
        if reason and reason not in log:raise AssertionError(name+': missing expected diagnostic')
        path=out/(name+'.execution.json')
        executed=[r for r in actions(path) if not r.get('cacheHit',False)] if path.exists() else []
        counts=collections.Counter(r['mnemonic'] for r in executed if r.get('targetLabel')=='//:version_map_qualification')
        item['executed_fixture_actions']=dict(counts)
        item['executed_compiles']=sum(r.get('mnemonic')=='CppCompile' for r in executed)
        print(name,done.returncode,dict(counts),flush=True)
        return item
    def compare(name,flags,required,absent=()):
        reference=out/(name+'-make');reference.mkdir()
        options=['VERSION_MAP=Fixture.map','VERSION_DEF='+str(versions),
                 'SYMBOL_MAPS='+str(first)+' '+str(second),'CFLAGS='+' '.join(flags)]
        log=env.query(['Fixture.map'],obj=reference,component=src/component['component'],extra=options)
        (out/(name+'-make.stdout')).write_text(log)
        native=workspace/'bazel-bin/version_map_qualification.map'
        text=native.read_text()
        if native.read_bytes()!=(reference/'Fixture.map').read_bytes():raise AssertionError(name+': Make/Bazel map mismatch')
        if any(s not in text for s in required) or any(s in text for s in absent):raise AssertionError(name+': unexpected symbols')
        (out/(name+'.map')).write_bytes(native.read_bytes())
    try:
        configure(baseflags);run('initial');compare('initial',baseflags,['qualified_first;','qualified_second;'])
        r=run('unchanged');assert not r['executed_fixture_actions'] and not r['executed_compiles']
        first.write_text(first_text.replace('qualified_first','qualified_changed'))
        r=run('source-change');assert r['executed_fixture_actions']=={'BSDVersionConcatenate':1,'BSDVersionPreprocess':1,'BSDVersionGenerate':1} and not r['executed_compiles']
        compare('source-change',baseflags,['qualified_changed;','qualified_second;'],['qualified_first;'])
        flags=['-DQUALIFY_FEATURE=1'];configure(flags)
        r=run('flags-change');assert r['executed_fixture_actions']=={'BSDVersionPreprocess':1,'BSDVersionGenerate':1} and not r['executed_compiles']
        compare('flags-change',flags,['qualified_changed;'],['qualified_second;'])
        configure(flags,reverse=True);run('wrong-order',False,'symbol map ordering lost')
        configure(flags);second.unlink();run('missing-input',False,'second.map')
        second.write_text(second_text);first.write_text(first_text);configure(baseflags)
        run('restored');compare('restored',baseflags,['qualified_first;','qualified_second;'])
        env.verify()
        receipt={'status':'passed','scope':'ordered symbol maps, configured flags, Make byte parity, failure propagation and action invalidation',
                 'cases':cases,'environment':env.receipt(),
                 'input_sha256':{str(p):digest(p) for p in [Path(__file__),args.plan,args.build_command,workspace/'configured_version_map.bzl',workspace/'toolchain/stdout_redirect.c']},
                 'limitations':['Synthetic multi-map cases do not qualify all base-library configurations.','No installation or world/kernel build claim.']}
        (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    finally:
        build.write_text(original)
        first.write_text(first_text);second.write_text(second_text)


if __name__=='__main__':main()
