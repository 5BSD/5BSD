#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify ordered repeated library inputs with native Bazel linking."""
import argparse,collections,json,os,shutil,subprocess,sys
from pathlib import Path
from libmd_environment import digest
parser=argparse.ArgumentParser(description=__doc__)
for key in ('inputs','bazel','output'):
 parser.add_argument('--'+key,type=Path,required=True)
args=parser.parse_args();root=args.output.resolve()
if root.exists() or not root.is_relative_to('/usr/obj') or root==Path('/usr/obj'):
 raise ValueError('fresh output below /usr/obj required')
root.mkdir();workspace=root/'workspace';workspace.mkdir()
settings=json.loads(args.inputs.read_text());sdk=Path(settings['toolchain-workspace']);receipt=json.loads(Path(settings['toolchain-receipt']).read_text())
for p,h in receipt['inputs'].items():assert digest(Path(p))==h,p
for p,h in receipt['snapshot'].items():assert digest(sdk/p)==h,p
shutil.copytree(sdk/'toolchain',workspace/'toolchain',symlinks=True)
rule=Path(__file__).with_name('bsd_link_sequence.bzl');rule_hash=digest(rule)
shutil.copyfile(rule,workspace/'bsd_link_sequence.bzl');shutil.copyfile(settings['module-lock'],workspace/'MODULE.bazel.lock')
(workspace/'MODULE.bazel').write_text('module(name="bsd_components")\nbazel_dep(name="rules_cc", version="0.2.17")\nbazel_dep(name="platforms", version="1.0.0")\nregister_toolchains("//toolchain:registered")\n')
for name,source in {'main.c':'int start(void); int support(void); int main(void) { return start()+support()==10 ? 0 : 1; }\n','a_start.c':'int middle(void); int start(void) { return middle(); }\n','a_tail.c':'int tail(void) { return 7; }\n','b.c':'int tail(void); int middle(void) { return tail(); }\n','support.c':'int support(void) { return 3; }\n'}.items():(workspace/name).write_text(source)
(workspace/'BUILD.bazel').write_text('''load("@rules_cc//cc:defs.bzl", "cc_library", "cc_binary")
load(":bsd_link_sequence.bzl", "bsd_link_sequence")
cc_library(name="a",srcs=["a_start.c","a_tail.c"])
cc_library(name="b",srcs=["b.c"])
filegroup(name="a_archive",srcs=[":a"],output_group="archive")
filegroup(name="b_archive",srcs=[":b"],output_group="archive")
cc_binary(name="libsupport.so",srcs=["support.c"],linkshared=True,linkopts=["-Wl,-soname,libsupport.so"])
bsd_link_sequence(name="sequence",members=[":a_archive",":b_archive",":libsupport.so"],order=[0,1,0,2])
cc_binary(name="probe",srcs=["main.c"],deps=[":sequence"],linkstatic=False,linkopts=["-Wl,-rpath,$$ORIGIN"])
''')
bazel=str(args.bazel);commands=[]
def run(name,expected=None,error=None):
 argv=[bazel,'--batch','--ignore_all_rc_files','--output_user_root='+str(root/'bazel-user-root'),'build','--lockfile_mode=error','--repository_disable_download','--repository_cache='+settings['repository-cache'],'--platforms=//toolchain:native','--host_platform=//toolchain:native','--jobs='+str(os.cpu_count()),'--noexecution_log_sort','--execution_log_json_file='+str(root/(name+'.execution.json')),*['--distdir='+p for p in settings['distdirs']],('//:invalid' if error else '//:probe')]
 with (root/(name+'.stdout')).open('w') as out,(root/(name+'.stderr')).open('w') as err:r=subprocess.run(['/usr/bin/time','-l',*argv],cwd=workspace,env=dict(os.environ,JAVA_HOME=settings['java-home'],LC_ALL='C',BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1'),stdout=out,stderr=err)
 commands.append(dict(name=name,exit_status=r.returncode));(root/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
 if error:
  assert r.returncode!=0 and error in (root/(name+'.stderr')).read_text(),name
  return
 assert r.returncode==0,name
 clean={'PATH':'/bin:/usr/bin','LC_ALL':'C'}
 binary=workspace/'bazel-bin/probe';library=workspace/'bazel-bin/libsupport.so'
 suite=root/'suite';suite.mkdir(exist_ok=True)
 if not (suite/'probe').exists():
  (suite/'probe').symlink_to(binary);(suite/'libsupport.so').symlink_to(library)
 for executable in (binary,suite/'probe'):
  trace=subprocess.run(['/usr/bin/ldd',str(executable)],env=clean,text=True,capture_output=True,check=True)
  selected=[line.split()[2] for line in trace.stdout.splitlines() if line.split()[:2]==['libsupport.so','=>']]
  assert len(selected)==1 and Path(selected[0]).resolve()==library.resolve(),trace.stdout
  result=subprocess.run([str(executable)],env=clean);assert result.returncode==expected,(name,result.returncode)

 params=(workspace/'bazel-bin/probe-0.params').read_text().splitlines();libraries=[Path(p).name for p in params if p.endswith(('.a','.so'))]
 assert libraries==['liba.a','libb.a','liba.a','libsupport.so'],libraries
run('cold',0);run('cached',0)
(workspace/'a_tail.c').write_text('int tail(void) { return 8; }\n');run('changed',1)
(workspace/'a_tail.c').write_text('int tail(void) { return 7; }\n');run('restored',0)
original=(workspace/'BUILD.bazel').read_text()
for name, order, message in [('bad-index',[0,3],'index out of range'),('unused',[0,0],'unused declared members'),('empty',[],'nonempty link sequence')]:
 (workspace/'BUILD.bazel').write_text(original+'\nbsd_link_sequence(name="invalid", members=[":a_archive",":b_archive",":libsupport.so"], order='+repr(order)+')\n')
 run(name,error=message)
(workspace/'BUILD.bazel').write_text(original)
decoder=json.JSONDecoder();actions={}
for name, expected in [('cold',{'CppCompile':5,'CppArchive':2,'CppLink':2}),('cached',{}),('changed',{'CppCompile':1,'CppArchive':1,'CppLink':1}),('restored',{'CppCompile':1,'CppArchive':1,'CppLink':1})]:
 text=(root/(name+'.execution.json')).read_text();counts=collections.Counter()
 while text.strip():
  text=text.lstrip();entry,end=decoder.raw_decode(text);text=text[end:];counts[entry.get('mnemonic')]+=1
 assert dict(counts)==expected,(name,counts)
 actions[name]=dict(counts)
assert digest(rule)==rule_hash
(root/'action-audit.json').write_text(json.dumps(dict(status='passed',actions=actions),indent=2)+'\n')
(root/'receipt.json').write_text(json.dumps(dict(status='passed',scope='native ordered repeated archive/shared library inputs and private source invalidation; not base program qualification',rule_sha256=rule_hash,actions=actions,input_sha256={str(args.inputs):digest(args.inputs),str(args.bazel):digest(args.bazel),str(Path(__file__)):digest(Path(__file__)),str(rule):rule_hash},commands=commands),indent=2)+'\n');print(root/'receipt.json')
