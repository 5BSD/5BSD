# SPDX-License-Identifier: BSD-2-Clause
"""Prepare and qualify a fresh libmd workspace from explicit reusable inputs."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

FILE_KEYS = ('profile', 'execution-tools', 'test-runtime', 'compression-tools', 'install-tools', 'module-lock')
DIR_KEYS = ('reference', 'java-home', 'repository-cache')

def digest(path):
    with Path(path).open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()

def validate(config, args):
    if not isinstance(config, dict) or set(config) != {'format', *FILE_KEYS, *DIR_KEYS, 'distdirs'} or type(config['format']) is not int or config['format'] != 2:
        raise ValueError('fresh qualification requires format 2 and exact documented fields')
    selected = {}
    for key in (*FILE_KEYS, *DIR_KEYS):
        value = config[key]
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise ValueError('absolute path required for '+key)
        p = Path(value).resolve(strict=True)
        if (key in FILE_KEYS and not p.is_file()) or (key in DIR_KEYS and not p.is_dir()):
            raise ValueError('wrong input type for '+key)
        selected[key] = p
    if not isinstance(config['distdirs'], list) or not config['distdirs']:
        raise ValueError('nonempty explicit distdirs required')
    dirs = []
    for value in config['distdirs']:
        if not isinstance(value, str) or not Path(value).is_absolute(): raise ValueError('absolute distdir required')
        p = Path(value).resolve(strict=True)
        if not p.is_dir(): raise ValueError('distdir is not a directory')
        dirs.append(p)
    selected['distdirs'] = dirs
    if not args.output.is_absolute(): raise ValueError('absolute output required')
    out = args.output.resolve()
    if args.output.is_symlink() or out.exists() or out == Path('/usr/obj') or not out.is_relative_to('/usr/obj'):
        raise ValueError('fresh output below /usr/obj required')
    protected = [args.src.resolve(strict=True), args.objtop.resolve(strict=True), args.inputs.resolve(strict=True), args.bazel.resolve(strict=True), *dirs, *[selected[k] for k in (*FILE_KEYS,*DIR_KEYS)]]
    for p in protected:
        if p==out or p.is_relative_to(out) or (p.is_dir() and out.is_relative_to(p)):
            raise ValueError('output overlaps an input: '+str(p))
    return out,selected

def prepare(config, args):
    out,selected = validate(config,args)
    scripts = args.src.resolve(strict=True)/'tools/build/bazel'
    bindings = {str(selected[k]):digest(selected[k]) for k in FILE_KEYS}
    bindings[str(args.inputs.resolve())] = digest(args.inputs)
    bindings[str(args.bazel.resolve())] = digest(args.bazel)
    for pattern in ('*.py','*.bzl'):
        bindings.update({str(p):digest(p) for p in scripts.glob(pattern)})
    out.mkdir(parents=True)
    commands=[]
    def run(name,argv):
        start=time.monotonic()
        with (out/(name+'.stdout')).open('w') as stdout,(out/(name+'.stderr')).open('w') as stderr:
            result=subprocess.run(['/usr/bin/time','-l',*argv],stdout=stdout,stderr=stderr)
        commands.append({'name':name,'argv':argv,'exit_status':result.returncode,'elapsed_seconds':time.monotonic()-start})
        (out/'preparation-commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if result.returncode: raise RuntimeError(name+' failed; see '+str(out/(name+'.stderr')))
    def helper(name,options):
        run(name,[sys.executable,'-B',str(scripts/(name+'.py')),*[str(x) for x in options]])
    common=['--src',args.src,'--objtop',args.objtop,'--profile',selected['profile']]
    graph=out/'graph';tests=out/'tests';library=out/'library-policy';directory=out/'directory-policy'
    try:
        helper('libmd-plan',common+['--output',graph])
        helper('libmd-stage-tools',['--plan',graph/'plan.json','--tools',selected['execution-tools']])
        helper('libmd-test-plan',common+['--output',tests])
        helper('libmd-install-plan',['--inventory',tests/'inventory.json','--output',out/'test-install-plan.json'])
        helper('libmd-library-install-plan',common+['--library-plan',graph/'plan.json','--reference',selected['reference'],'--output',library])
        helper('libmd-directory-plan',common+['--library-policy',library/'inventory.json','--test-policy',out/'test-install-plan.json','--reference',selected['reference'],'--output',directory])
        shutil.copyfile(selected['module-lock'],graph/'workspace/MODULE.bazel.lock')
        inputs={'format':1,'plan':str(graph/'plan.json'),'test-plan':str(tests/'inventory.json'),'install-plan':str(out/'test-install-plan.json'),'library-install-plan':str(library/'inventory.json'),'directory-policy':str(directory/'inventory.json'),'toolchain-receipt':str(graph/'toolchain-inputs.json'),'output-user-root':str(out/'bazel-user-root'),'distdirs':[str(p) for p in selected['distdirs']]}
        for k in ('test-runtime','compression-tools','install-tools','java-home','repository-cache'):inputs[k]=str(selected[k])
        (out/'prepared-inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
        helper('native-qualify',['--src',args.src,'--objtop',args.objtop,'--bazel',args.bazel,'--inputs',out/'prepared-inputs.json','--output',out/'qualification','--jobs',args.jobs])
        for p,h in bindings.items():
            if digest(p)!=h:raise ValueError('preparation input changed: '+p)
        report=json.loads((out/'qualification/receipt.json').read_text())
        report['preparation']={'status':'passed','fresh_workspace':True,'commands':commands,'inputs':bindings,'limitations':['Reuses the explicitly selected Make-built SDK, tool binaries and Make installation reference.','Module lock and repository download cache are reusable inputs; action cache starts empty.']}
        (out/'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
        print(out/'receipt.json')
    except Exception as e:
        (out/'FAILED.json').write_text(json.dumps({'status':'failed','error':str(e),'commands':commands},indent=2)+'\n')
        raise
