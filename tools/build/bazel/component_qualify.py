# SPDX-License-Identifier: BSD-2-Clause
"""Qualify a configured component graph, native tests, stage and selected archives."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from libmd_environment import digest
import stage_verify
import atf_results
import component_plans
import component_labels

FILE_KEYS=('plan','toolchain-receipt','module-lock','test-config','directory-policy','compression-tools','install-tools','profile','pkg','flua')
DIR_KEYS=('toolchain-workspace','java-home','repository-cache')

def qualify(config,args):
    build_only=type(config.get('format')) is int and config['format']==4
    file_keys=(('plan','toolchain-receipt','module-lock','profile')+ (('test-config',) if 'test-config' in config else ())) if build_only else FILE_KEYS
    if 'test-result-sqlite' in config:file_keys+=('test-result-sqlite',)
    list_keys=('distdirs',) if build_only else ('component-policies','distdirs')
    if 'additional-plans' in config:list_keys+=('additional-plans',)
    required={'format',*file_keys,*DIR_KEYS,*list_keys}
    if 'execution-log-format' in config:required.add('execution-log-format')
    log_format=config.get('execution-log-format','json')
    if log_format not in ('json','compact'):raise ValueError('execution-log-format must be json or compact')
    if 'program-runtime-libraries' in config:required.add('program-runtime-libraries')
    program_runtimes=config.get('program-runtime-libraries',[])
    if not isinstance(program_runtimes,list) or any(not isinstance(n,str) or not n for n in program_runtimes) or len(set(program_runtimes))!=len(program_runtimes):
        raise ValueError('unique nonempty program runtime library names required')
    if not build_only:required.update(('package-component','abi-file'))
    if set(config)!=required or type(config['format']) is not int or config['format'] not in (3,4):
        raise ValueError('component qualification requires exact format-3 or format-4 fields')
    selected={}
    for k in (*file_keys,*DIR_KEYS):
        v=config[k]
        if not isinstance(v,str) or not Path(v).is_absolute():raise ValueError('absolute path required: '+k)
        p=Path(v).resolve(strict=True)
        if not (p.is_file() if k in file_keys else p.is_dir()):raise ValueError('wrong input type: '+k)
        selected[k]=p
    for k in list_keys:
        if not isinstance(config[k],list) or not config[k]:raise ValueError('nonempty path list required: '+k)
        selected[k]=[]
        for v in config[k]:
            if not isinstance(v,str) or not Path(v).is_absolute():raise ValueError('absolute input required')
            p=Path(v).resolve(strict=True)
            if not (p.is_file() if k in ('component-policies','additional-plans') else p.is_dir()):raise ValueError('wrong list input type')
            selected[k].append(p)
    for k in (() if build_only else ('package-component','abi-file')):
        v=config[k]
        if not isinstance(v,str) or not v or Path(v).is_absolute() or '..' in Path(v).parts:raise ValueError('source/stage relative input required: '+k)
    out=args.output.resolve();src=args.src.resolve(strict=True)
    protected=[src,args.objtop.resolve(strict=True),args.inputs.resolve(strict=True),args.bazel.resolve(strict=True),
               *[selected[k] for k in (*file_keys,*DIR_KEYS)],*selected.get('component-policies',[]),*selected.get('additional-plans',[]),*selected['distdirs']]
    if (not args.output.is_absolute() or args.output.is_symlink() or out.exists() or out==Path('/usr/obj') or
        not out.is_relative_to('/usr/obj') or any(p==out or p.is_relative_to(out) or (p.is_dir() and out.is_relative_to(p)) for p in protected)):
        raise ValueError('fresh nonoverlapping output under /usr/obj required')
    plan=component_plans.load([selected['plan'],*selected.get('additional-plans',[])],src)
    if plan['build_environment']['objtop']!=str(args.objtop.resolve()) or plan['build_environment']['input_sha256'].get(str(selected['profile']))!=digest(selected['profile']):
        raise ValueError('component plan does not match selected object/profile')
    components={c['component']:c for c in plan['components']}
    if not build_only and len(components)!=len(plan['components']):raise ValueError('multi-program component installation policy requires explicit support; format 4 can qualify its build/tests')
    policies=[json.loads(p.read_text()) for p in selected.get('component-policies',[])]
    if not build_only and (len(policies)!=len(components) or {p.get('component') for p in policies}!=set(components)):
        raise ValueError('every selected component requires exactly one installation policy')
    names=[component_labels.artifact(components[p['component']],components[p['component']]['metadata']['LIB'] or components[p['component']]['metadata']['PROG']) for p in policies]
    scripts=src/'tools/build/bazel'
    bindings={str(p):digest(p) for p in protected if p.is_file()}
    bindings.update({str(p):digest(p) for pattern in ('*.py','*.bzl') for p in scripts.glob(pattern)})
    workspace=out/'workspace';out.mkdir();commands=[]
    def run(name,argv,cwd=None,env=None):
        start=time.monotonic()
        with (out/(name+'.stdout')).open('w') as stdout,(out/(name+'.stderr')).open('w') as stderr:
            result=subprocess.run(['/usr/bin/time','-l',*[str(x) for x in argv]],cwd=cwd,env=env,stdout=stdout,stderr=stderr)
        commands.append({'name':name,'argv':[str(x) for x in argv],'exit_status':result.returncode,'elapsed_seconds':time.monotonic()-start})
        (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if result.returncode:raise RuntimeError(name+' failed; see '+str(out/(name+'.stderr')))
    def helper(name,values):run(name,[sys.executable,'-B',scripts/(name+'.py'),*values])
    try:
        values=['--src',src,'--output',workspace]
        for k in ('plan','toolchain-receipt','toolchain-workspace','module-lock','test-config','directory-policy','compression-tools','install-tools'):
            if k in selected:values+=['--'+k,selected[k]]
        for p in selected.get('additional-plans',[]):values+=['--additional-plan',p]
        for p in selected.get('component-policies',[]):values+=['--component-install-plan',p]
        for name in program_runtimes:values+=['--program-runtime-library',name]
        helper('component-build',values)
        has_atf=(workspace/'configured-test-policy.json').is_file() and bool(json.loads((workspace/'configured-test-policy.json').read_text()))
        if has_atf and 'test-result-sqlite' not in selected:
            raise ValueError('configured ATF qualification requires explicit test-result-sqlite tool')
        expected=json.loads((workspace/'native-test-inventory.json').read_text())['labels']
        if not expected or len(expected)!=len(set(expected)):raise ValueError('nonempty unique native test inventory required')
        bazel=[args.bazel,'--batch','--ignore_all_rc_files','--output_user_root='+str(out/'bazel-user-root'),'test',
               '--compilation_mode=opt','--strip=never','--lockfile_mode=error','--repository_disable_download',
               '--repository_cache='+str(selected['repository-cache']),'--platforms=//toolchain:native','--host_platform=//toolchain:native',
               '--extra_execution_platforms=//toolchain:native','--jobs='+str(args.jobs),'--test_output=errors',
               '--build_event_json_file='+str(out/'events.json'),'--noexecution_log_sort', '--execution_log_'+('compact' if log_format=='compact' else 'json')+'_file='+str(out/('execution.'+log_format)),
               *['--distdir='+str(p) for p in selected['distdirs']],'//...']
        env={'PATH':'/bin:/usr/bin:/usr/local/bin','HOME':os.environ['HOME'],'LC_ALL':'C','JAVA_HOME':str(selected['java-home']),'BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN':'1'}
        run('bazel-test',bazel,workspace,env)
        log_path=out/('execution.'+log_format)
        log_record=dict(format=log_format,path=str(log_path),sha256=digest(log_path),bytes=log_path.stat().st_size)
        tests={}
        for line in (out/'events.json').read_text().splitlines():
            event=json.loads(line)
            if 'testSummary' in event:tests[event['id']['testSummary']['label']]=event['testSummary']['overallStatus']
        if set(tests)!=set(expected) or set(tests.values())!={'PASSED'}:raise ValueError('native test inventory/status mismatch')
        runtime_receipts=[]
        inventory=json.loads((workspace/'native-test-inventory.json').read_text())
        for check in inventory.get('runtime_checks',[]):
            check_name=atf_results.artifact_path(check['name'])
            invocation=atf_results.runtime_binary(workspace,check)
            library_paths={soname:atf_results.artifact_path(path) for soname,path in check['libraries'].items()}
            destination=out/'runtime-checks'/check_name/'result'
            destination.parent.mkdir(parents=True,exist_ok=True)
            argv=[sys.executable,'-B',scripts/'elf-runtime-check.py','--binary',invocation,'--output',destination]
            for soname,artifact in library_paths.items():
                argv+=['--library',soname+'='+str(workspace/'bazel-bin'/artifact)]
            argv+=['--argument='+argument for argument in check.get('args',[])]
            command_name='runtime-checks/'+str(check_name)+'/check'
            run(command_name,argv)
            runtime_receipts.append(json.loads((destination/'receipt.json').read_text()))
        atf_summary=None
        if has_atf:
            result_path=out/'atf-results-receipt.json'
            result=atf_results.verify(workspace,selected['test-result-sqlite'],result_path)
            atf_summary={k:result[k] for k in ('programs','cases','case_counts','all_cases_passed')}
            atf_summary.update(receipt=str(result_path),sha256=digest(result_path))
        if build_only:
            for p,h in bindings.items():
                if digest(Path(p))!=h:raise ValueError('qualification input changed: '+p)
            receipt={'status':'passed','scope':'selected component native build and tests only',
                     'tests':tests,'runtime_checks':runtime_receipts,'atf_case_results':atf_summary,'execution_log':log_record,'input_sha256':bindings,
                     'limitations':['Prepared SDK reused; other system runtime libraries remain host supplied.',
                                    'No installation, package, publication, full-system or performance qualification.']}
            (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(out/'receipt.json')
            return
        parity=stage_verify.verify(workspace,selected['directory-policy'],component_plans=selected['component-policies'],manifest_names=names)
        (out/'stage-parity.json').write_text(json.dumps(parity,indent=2)+'\n')
        values=['--src',src,'--objtop',args.objtop,'--workspace',workspace,'--output',out/'packages','--jobs',str(args.jobs)]
        for k in ('profile','directory-policy','pkg','flua'):values+=['--'+k,selected[k]]
        for k in ('package-component','abi-file'):values+=['--'+k,config[k]]
        for p in selected['component-policies']:values+=['--component-policy',p]
        for n in names:values+=['--manifest-name',n]
        helper('component-packages',values)
        packages=json.loads((out/'packages/receipt.json').read_text())
        for p,h in bindings.items():
            if digest(Path(p))!=h:raise ValueError('qualification input changed: '+p)
        receipt={'status':'passed','scope':'selected component native build/tests/stage and Make-created archives',
                 'tests':tests,'runtime_checks':runtime_receipts,'atf_case_results':atf_summary,'execution_log':log_record,'stage_parity':parity,'archives':packages['archives'],'input_sha256':bindings,
                 'limitations':['Prepared SDK and Make references reused.','Runtime/package installation, dependency solver, sandbox and full-system qualification remain separate.']}
        (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(out/'receipt.json')
    except Exception as error:
        (out/'FAILED.json').write_text(json.dumps({'status':'failed','error':str(error)},indent=2)+'\n')
        raise
