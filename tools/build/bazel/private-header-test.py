#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify private header ownership, dependent isolation and invalidation."""
import argparse,json,os,shutil,subprocess
from pathlib import Path
from libmd_environment import digest

p=argparse.ArgumentParser(description=__doc__)
for key in ('workspace','command-log','java-home','output'):
    p.add_argument('--'+key,type=Path,required=True)
a=p.parse_args();origin=a.workspace.resolve(strict=True);out=a.output.resolve()
if out.exists() or not out.is_relative_to('/usr/obj') or out==Path('/usr/obj') or origin.is_relative_to(out):
    p.error('fresh nonoverlapping output below /usr/obj required')
argv=next(c['argv'] for c in json.loads(a.command_log.read_text()) if c['name']=='bazel-test')
if argv[-1]!='//...' or '--repository_disable_download' not in argv or '--ignore_all_rc_files' not in argv:
    p.error('explicit offline test command required')
out.mkdir();w=out/'workspace';w.mkdir();(w/'private').mkdir()
shutil.copytree(origin/'toolchain',w/'toolchain',symlinks=True)
for name in ('MODULE.bazel','MODULE.bazel.lock'):shutil.copyfile(origin/name,w/name)
inputs={}
for name in ('native_cc.bzl','bsd_dtrace.bzl','bsd_fidl.bzl','source_identity.bzl'):
    path=Path(__file__).with_name(name);inputs[str(path)]=digest(path);shutil.copyfile(path,w/name)
files={'api.h':'int private_value(void); int ordinary_value(void);\n',
       'private/implementation.h':'#define PRIVATE_VALUE 17\n',
       'private_source.c':'#include "api.h"\n#include "implementation.h"\nint private_value(void) { return PRIVATE_VALUE; }\n',
       'ordinary.c':'#include "api.h"\nint ordinary_value(void) { return 5; }\n',
       'consumer.c':'#include "api.h"\nint main(void) { return private_value()+ordinary_value()!=22; }\n',
       'forbidden.c':'#include "implementation.h"\nint main(void) { return PRIVATE_VALUE!=17; }\n'}
for name,text in files.items():(w/name).write_text(text)
(w/'BUILD.bazel').write_text('''load(":native_cc.bzl", "bsd_library")
load("@rules_cc//cc:defs.bzl", "cc_test")
bsd_library(name="library", srcs=["private_source.c", "ordinary.c"], hdrs=["api.h"], textual_inputs=["private/implementation.h"], source_textual_inputs={"private_source.c":["private/implementation.h"]}, per_file_flags={"private_source.c":["-Iprivate"]}, variants=["regular"], arflags=["-crsD"], archive_inputs="//toolchain:archive_inputs")
cc_test(name="consumer", srcs=["consumer.c"], deps=[":library"], linkstatic=True, size="small")
cc_test(name="forbidden", srcs=["forbidden.c"], deps=[":library"], copts=["-Iprivate"], tags=["manual"], size="small")
''')
argv=[('--output_user_root='+str(out/'bazel-root') if x.startswith('--output_user_root=') else x) for x in argv]
env=dict(os.environ,JAVA_HOME=str(a.java_home.resolve(strict=True)),BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1')
records=[]
def entries(path):
    text=path.read_text();decoder=json.JSONDecoder();offset=0
    while offset<len(text):
        while offset<len(text) and text[offset].isspace():offset+=1
        if offset==len(text):return
        row,offset=decoder.raw_decode(text,offset);yield row

def run(name,target='//:consumer',build=False):
    command=[('build' if x=='test' and build else '--build_event_json_file='+str(out/(name+'.events.json')) if x.startswith('--build_event_json_file=') else '--execution_log_json_file='+str(out/(name+'.execution.json')) if x.startswith(('--execution_log_json_file=', '--execution_log_compact_file=')) else x) for x in argv[:-1]]+[target]
    with (out/(name+'.stdout')).open('w') as stdout,(out/(name+'.stderr')).open('w') as stderr:
        result=subprocess.run(['/usr/bin/time','-l',*command],cwd=w,env=env,stdout=stdout,stderr=stderr)
    records.append(dict(name=name,argv=command,exit_status=result.returncode))
    (out/'commands.json').write_text(json.dumps(records,indent=2)+'\n')
    return result.returncode
assert run('baseline')==0
compile_inputs={}
for row in entries(out/'baseline.execution.json'):
    if row.get('mnemonic')!='CppCompile':continue
    command=row['commandArgs'];source=command[command.index('-c')+1]
    compile_inputs[source]={item['path'] for item in row['inputs']}
assert 'private/implementation.h' in compile_inputs['private_source.c']
for name in ('ordinary.c','consumer.c'):
    assert 'private/implementation.h' not in compile_inputs[name], 'private header leaked to '+name
assert run('forbidden',target='//:forbidden')!=0
assert "'implementation.h' file not found" in (out/'forbidden.stderr').read_text()
header=w/'private/implementation.h';original=header.read_bytes();before=digest(w/'bazel-bin/liblibrary.a')
try:
    header.write_text('#define PRIVATE_VALUE 18\n')
    assert run('changed',build=True)==0
    compiled=[]
    for row in entries(out/'changed.execution.json'):
        if row.get('mnemonic')=='CppCompile' and not row.get('cacheHit',False):
            command=row['commandArgs'];compiled.append(command[command.index('-c')+1])
    assert compiled==['private_source.c'],compiled
finally:
    header.write_bytes(original)
assert run('restored')==0
assert digest(w/'bazel-bin/liblibrary.a')==before
for path,sha in inputs.items():assert digest(Path(path))==sha
(out/'receipt.json').write_text(json.dumps(dict(status='passed',scope='private header input ownership; dependent isolation; single-source mutation build; runtime restoration',records=records,inputs=inputs,compile_input_counts={name:len(paths) for name,paths in compile_inputs.items()},changed_compile_sources=compiled,limitations=['No complete libc build or matched performance qualification.']),indent=2)+'\n')
print('PASS: private header isolated; consumer denied access; one-source invalidation; byte-identical restoration')
