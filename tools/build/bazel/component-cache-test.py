#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify same-name component cache isolation on a maintained emitted graph.

Only the private emitted source snapshot is changed. The selected program is
built, never invoked by this driver. Test execution follows the explicit input
configuration's declared test inventory.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.parse import urlparse, unquote
import component_labels
import component_plans
from libmd_environment import digest

p=argparse.ArgumentParser(description=__doc__)
for name in ('inputs','bazel','output','source'):p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--component',required=True)
p.add_argument('--src',type=Path,default=Path('/usr/src'))
a=p.parse_args();src=a.src.resolve(strict=True);out=a.output.resolve()
if out.exists() or not out.is_relative_to('/usr/obj') or out==Path('/usr/obj') or out.is_relative_to(src) or src.is_relative_to(out):
    raise ValueError('fresh nonoverlapping output below /usr/obj required')
source_relative=component_labels.relative(str(a.source));source=src/source_relative
config=json.loads(a.inputs.read_text())
if config.get('format')!=4:raise ValueError('explicit format-4 native test configuration required')
plan=component_plans.load([config['plan'],*config.get('additional-plans',[])],src)
selected=[c for c in plan['components'] if c['component']==a.component]
if len(selected)!=1 or not selected[0]['metadata']['PROG']:
    raise ValueError('one configured program component required')
component=selected[0];name=component['metadata']['PROG']
owners={c['component'] for c in plan['components'] for s in c['sources'] if s.get('path')==source_relative}
if owners!={a.component} or not any(s.get('path')==source_relative and s['resolution']=='source' and s['name'].endswith('.c') for s in component['sources']):
    raise ValueError('selected C source must belong only to the tested program component')
collisions=[c for c in plan['components'] if (c['metadata']['LIB'] or c['metadata']['PROG'])==name]
if len(collisions)<2:raise ValueError('actual duplicate primary target names required')
target=component_labels.label(component,name);prefix='//'+component_labels.package(component)+':'
targets={component_labels.label(c,name) for c in collisions}
scripts=Path(__file__).resolve().parent
bindings={str(path):digest(path) for path in (a.inputs.resolve(),a.bazel.resolve(),source)}
bindings.update({str(path):digest(path) for pattern in ('*.py','*.bzl') for path in scripts.glob(pattern)})
out.mkdir();w=out/'workspace';commands=[]
def execute(name,argv,cwd=None):
    with (out/(name+'.stdout')).open('w') as stdout,(out/(name+'.stderr')).open('w') as stderr:
        result=subprocess.run(['/usr/bin/time','-l',*[str(v) for v in argv]],cwd=cwd,env=dict(os.environ,JAVA_HOME=config['java-home'],LC_ALL='C',BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1'),stdout=stdout,stderr=stderr)
    commands.append(dict(name=name,argv=[str(v) for v in argv],exit_status=result.returncode))
    (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    if result.returncode:raise RuntimeError(name+' failed; see retained stderr')
emit=[sys.executable,'-B',scripts/'component-build.py','--src',src,'--output',w]
for key in ('plan','toolchain-receipt','toolchain-workspace','module-lock','test-config'):
    if key in config:emit+=['--'+key,config[key]]
for path in config.get('additional-plans',[]):emit+=['--additional-plan',path]
for runtime in config.get('program-runtime-libraries',[]):emit+=['--program-runtime-library',runtime]
execute('emit',emit)
expected=set(json.loads((w/'native-test-inventory.json').read_text())['labels'])
if not expected:raise ValueError('nonempty explicit test inventory required')
private=w/'sources'/source_relative;original=private.read_bytes()
if digest(private)!=bindings[str(source)]:raise ValueError('source snapshot differs')
marker=b'bsd_bazel_private_cache_probe'
if marker in original:raise ValueError('fixture symbol already present')
actions={};outputs={}
def execution_rows(path):
    text=path.read_text();decoder=json.JSONDecoder();offset=0
    while offset<len(text):
        while offset<len(text) and text[offset].isspace():offset+=1
        if offset==len(text):return
        row,offset=decoder.raw_decode(text,offset);yield row

def run(name):
    argv=[a.bazel,'--batch','--ignore_all_rc_files','--output_user_root='+str(out/'bazel-root'),'test','--compilation_mode=opt','--strip=never','--lockfile_mode=error','--repository_disable_download','--repository_cache='+config['repository-cache'],'--platforms=//toolchain:native','--host_platform=//toolchain:native','--extra_execution_platforms=//toolchain:native','--jobs='+str(os.cpu_count()),'--test_output=errors','--noexecution_log_sort','--execution_log_json_file='+str(out/(name+'.execution.json')),'--build_event_json_file='+str(out/(name+'.events.json')),*['--distdir='+v for v in config['distdirs']],'//...']
    execute(name,argv,w)
    rows=list(execution_rows(out/(name+'.execution.json')))
    actions[name]=[dict(mnemonic=r.get('mnemonic'),target=r.get('targetLabel')) for r in rows]
    tests={};sets={};completed={}
    for line in (out/(name+'.events.json')).read_text().splitlines():
        event=json.loads(line)
        if 'testSummary' in event:tests[event['id']['testSummary']['label']]=event['testSummary']['overallStatus']
        if 'namedSetOfFiles' in event:sets[event['id']['namedSet']['id']]=event['namedSetOfFiles']
        if 'completed' in event:completed[event['id']['targetCompleted']['label']]=event['completed']
    if set(tests)!=expected or set(tests.values())!={'PASSED'}:raise ValueError('test inventory/status differs')
    artifacts={}
    for label in sorted(targets):
        record=completed[label]
        if not record['success']:raise ValueError('collision target failed: '+label)
        pending=[v['id'] for group in record.get('outputGroup',[]) if group['name']=='default' for v in group.get('fileSets',[])];seen=set();files={}
        while pending:
            key=pending.pop()
            if key in seen:continue
            seen.add(key);group=sets[key];pending.extend(v['id'] for v in group.get('fileSets',[]))
            for file in group.get('files',[]):
                uri=urlparse(file['uri']);path=Path(unquote(uri.path)).resolve(strict=True)
                if uri.scheme!='file' or uri.netloc or not path.is_relative_to(out):raise ValueError('output outside private qualification')
                sha=digest(path)
                if sha!=file['digest'] or path.stat().st_size!=int(file['length']):raise ValueError('declared artifact differs')
                files[file['name']]=sha
        if not files:raise ValueError('empty declared output group')
        artifacts[label]=files
    outputs[name]=artifacts
run('cold');run('cached')
if actions['cached']:raise ValueError('unchanged graph executed actions')
try:
    private.write_bytes(original+b'\nint bsd_bazel_private_cache_probe(void);\nint bsd_bazel_private_cache_probe(void) { return 147; }\n')
    run('changed')
finally:
    private.write_bytes(original)
run('restored')
compiled=[row for row in actions['changed'] if row['mnemonic']=='CppCompile']
if len(compiled)!=1 or not compiled[0]['target'].startswith(prefix):raise ValueError('source mutation did not isolate compilation')
if any(not row['target'] or not row['target'].startswith(prefix) for row in actions['changed']):raise ValueError('unrelated component executed actions after mutation')
if not any(row['mnemonic']=='CppLink' for row in actions['changed']):raise ValueError('changed program was not relinked')
if outputs['changed'][target]==outputs['cold'][target]:raise ValueError('fixture mutation did not change program artifact')
for label in targets-{target}:
    if outputs['changed'][label]!=outputs['cold'][label]:raise ValueError('same-name unrelated artifact changed')
if outputs['restored']!=outputs['cold']:raise ValueError('restored outputs differ')
if private.read_bytes()!=original:raise ValueError('private source not restored')
for path,value in bindings.items():
    if digest(Path(path))!=value:raise ValueError('maintained input changed: '+path)
(out/'receipt.json').write_text(json.dumps(dict(status='passed',scope='actual emitted same-name component cache isolation, private source invalidation/restoration and explicit regression tests; selected program is not executed by this driver',component=a.component,source=source_relative,actions=actions,outputs=outputs,tests=sorted(expected),input_sha256=bindings,commands=commands),indent=2)+'\n')
print(out/'receipt.json')
