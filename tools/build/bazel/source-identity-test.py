#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify explicit source metadata across nested Bazel packages and generators."""
import argparse,collections,json,os,shutil,subprocess
from pathlib import Path
from libmd_environment import digest
p=argparse.ArgumentParser(description=__doc__)
for key in ('inputs','bazel','output'):p.add_argument('--'+key,type=Path,required=True)
a=p.parse_args();out=a.output.resolve()
if out.exists() or not out.is_relative_to('/usr/obj') or out==Path('/usr/obj'):raise ValueError('fresh output below /usr/obj required')
config=json.loads(a.inputs.read_text());sdk=Path(config['toolchain-workspace']);sdk_receipt=json.loads(Path(config['toolchain-receipt']).read_text())
for path,value in sdk_receipt['inputs'].items():assert digest(Path(path))==value,path
for path,value in sdk_receipt['snapshot'].items():assert digest(sdk/path)==value,path
out.mkdir();w=out/'workspace';w.mkdir();shutil.copytree(sdk/'toolchain',w/'toolchain',symlinks=True)
inputs={str(a.inputs):digest(a.inputs),str(a.bazel):digest(a.bazel),str(Path(__file__)):digest(Path(__file__))}
for name in ('native_cc.bzl','bsd_program.bzl','source_identity.bzl','bsd_dtrace.bzl','bsd_fidl.bzl'):
 source=Path(__file__).with_name(name);inputs[str(source)]=digest(source);shutil.copyfile(source,w/name)
shutil.copyfile(config['module-lock'],w/'MODULE.bazel.lock')
(w/'MODULE.bazel').write_text('module(name="bsd_components")\nbazel_dep(name="rules_cc", version="0.2.17")\nbazel_dep(name="platforms", version="1.0.0")\nregister_toolchains("//toolchain:registered")\n')
(w/'BUILD.bazel').write_text('')
(w/'inputs').mkdir()
(w/'inputs/lib.c').write_text('#include BODY\nint value(void) { return VALUE; }\n')
(w/'inputs/main.c').write_text('int value(void); int main(void) { return value()!=EXPECTED; }\n')
(w/'inputs/left.h').write_text('#define VALUE 7\n');(w/'inputs/right.h').write_text('#define VALUE 9\n')
(w/'inputs/BUILD.bazel').write_text('exports_files(["lib.c", "main.c", "left.h", "right.h"])\n')
def rule(kind,**attrs):return kind+'('+', '.join(k+'='+repr(v) for k,v in attrs.items())+')'
for package,value in (('left',7),('right',9)):
 directory=w/package;directory.mkdir();header='//inputs:'+package+'.h'
 flags=['-Iinputs','-DBODY="'+package+'.h"']
 attrs=dict(name='library',srcs=['//inputs:lib.c'],source_keys={'//inputs:lib.c':'library-unit'},textual_inputs=[header],textual_keys={header:'private-body'},source_textual_inputs={'library-unit':['private-body']},source_variants={'library-unit':['regular','pic']},source_variant_flags={'library-unit|regular':flags,'library-unit|pic':flags+['-fpic','-DPIC']},archive_object_names={'library-unit|regular':'configured.o','library-unit|pic':'configured.pic.o'},archive_member_order={'regular':['configured.o'],'pic':['configured.pic.o']},variants=['regular','pic'],arflags=['-crsD'],archive_inputs='//toolchain:archive_inputs')
 lines=['load("//:native_cc.bzl", "bsd_library", "bsd_source_alias")','load("//:bsd_program.bzl", "bsd_program_objects")','load("@rules_cc//cc:defs.bzl", "cc_binary")',rule('bsd_library',**attrs),rule('filegroup',name='pic',srcs=[':library'],output_group='pic_archive'),rule('bsd_source_alias',name='main_alias',source='//inputs:main.c',output='generated.c'),rule('bsd_program_objects',name='objects',srcs=[':main_alias'],source_keys={':main_alias':'main-unit'},source_order=['main-unit'],source_flags={'main-unit':['-DEXPECTED='+str(value)]}),rule('cc_binary',name='probe',srcs=[':objects'],deps=[':library'],linkstatic=True)]
 (directory/'BUILD.bazel').write_text('\n'.join(lines)+'\n')
commands=[];action_counts={};compile_targets={}
def entries(path):
 text=path.read_text();decoder=json.JSONDecoder();offset=0
 while offset<len(text):
  while offset<len(text) and text[offset].isspace():offset+=1
  if offset==len(text):return
  row,offset=decoder.raw_decode(text,offset);yield row

def run(name,negative=None,message=None):
 targets=[negative] if negative else ['//left:probe','//right:probe','//left:library','//right:library','//left:pic','//right:pic']
 argv=[str(a.bazel),'--batch','--ignore_all_rc_files','--output_user_root='+str(out/'bazel-root'),'build','--lockfile_mode=error','--repository_disable_download','--repository_cache='+config['repository-cache'],'--platforms=//toolchain:native','--host_platform=//toolchain:native','--jobs='+str(os.cpu_count()),'--noexecution_log_sort','--execution_log_json_file='+str(out/(name+'.execution.json')),*['--distdir='+d for d in config['distdirs']],*targets]
 with (out/(name+'.stdout')).open('w') as stdout,(out/(name+'.stderr')).open('w') as stderr:r=subprocess.run(['/usr/bin/time','-l',*argv],cwd=w,env=dict(os.environ,JAVA_HOME=config['java-home'],LC_ALL='C',BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1'),stdout=stdout,stderr=stderr)
 commands.append(dict(name=name,argv=argv,exit_status=r.returncode));(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
 if negative:
  assert r.returncode!=0 and message in (out/(name+'.stderr')).read_text(),name
  return
 assert r.returncode==0,name
 rows=list(entries(out/(name+'.execution.json')))
 action_counts[name]=dict(collections.Counter(row.get('mnemonic') for row in rows))
 compile_targets[name]=[row['targetLabel'] for row in rows if row.get('mnemonic')=='CppCompile']
 for package in ('left','right'):
  expected=1 if name=='changed' and package=='left' else 0
  result=subprocess.run([str(w/'bazel-bin'/package/'probe')],env={'PATH':'/bin:/usr/bin','LC_ALL':'C'})
  assert result.returncode==expected,(name,package,result.returncode)
run('cold');run('cached')
(w/'inputs/left.h').write_text('#define VALUE 8\n');run('changed')
(w/'inputs/left.h').write_text('#define VALUE 7\n');run('restored')
assert len(compile_targets['cold'])==6,compile_targets
assert not compile_targets['cached']
for name in ('changed','restored'):
 assert compile_targets[name]==['//left:library','//left:library'],compile_targets[name]
 assert action_counts[name].get('BSDNativeArchive')==2 and action_counts[name].get('CppLink')==1,action_counts[name]
archives={}
for package in ('left','right'):
 for suffix,member in (('.a','configured.o'),('.pic.a','configured.pic.o')):
  archive=w/'bazel-bin'/package/('liblibrary'+suffix)
  members=subprocess.check_output([str(w/'toolchain/bin/llvm-ar'),'t',str(archive)],text=True).splitlines();assert members==[member],members
  archives[str(archive.relative_to(w/'bazel-bin'))]=dict(members=members,sha256=digest(archive))
bad=w/'invalid';bad.mkdir()
base=['load("//:bsd_program.bzl", "bsd_program_objects")','filegroup(name="multiple", srcs=["//inputs:main.c", "//inputs:lib.c"])']
for name,srcs,keys,message in [('partial',['//inputs:main.c','//inputs:lib.c'],{'//inputs:main.c':'unit'},'identities must cover every declared file'),('duplicate',['//inputs:main.c','//inputs:lib.c'],{'//inputs:main.c':'unit','//inputs:lib.c':'unit'},'unique nonempty'),('extra',['//inputs:main.c'],{'//inputs:lib.c':'unit'},'does not select one declared file'),('multiple',[':multiple'],{':multiple':'unit'},'one file required')]:
 (bad/'BUILD.bazel').write_text('\n'.join(base+[rule('bsd_program_objects',name='bad',srcs=srcs,source_keys=keys,source_order=['unit'],source_flags={'unit':[]})])+'\n')
 run('bad-'+name,'//invalid:bad',message)
for path,value in inputs.items():assert digest(Path(path))==value,path
(out/'receipt.json').write_text(json.dumps(dict(status='passed',scope='native nested-package program/library source identity, generated source, private input invalidation and invalid-map rejection; not component emitter namespace qualification',actions=action_counts,compile_targets=compile_targets,archives=archives,input_sha256=inputs,commands=commands),indent=2)+'\n');print(out/'receipt.json')
