#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify native C/C++ program objects, constructor retention and cache changes."""
import argparse,json,os,shutil,subprocess,sys,time
from pathlib import Path
from libmd_environment import digest
parser=argparse.ArgumentParser(description=__doc__)
for key in ('inputs','bazel','output'):
 parser.add_argument('--'+key,type=Path,required=True)
parser.add_argument('--pic',action='store_true')
args=parser.parse_args()
settings=json.loads(args.inputs.read_text())
root=args.output.resolve()
if root.exists() or not root.is_relative_to('/usr/obj') or root==Path('/usr/obj'):
 raise ValueError('fresh output below /usr/obj required')
root.mkdir();workspace=root/'workspace';workspace.mkdir()
sdk=Path(settings['toolchain-workspace']);receipt=json.loads(Path(settings['toolchain-receipt']).read_text())
for path,sha in receipt['inputs'].items():assert digest(Path(path))==sha,path
for path,sha in receipt['snapshot'].items():assert digest(sdk/path)==sha,path
shutil.copytree(sdk/'toolchain',workspace/'toolchain',symlinks=True)
rule=Path(__file__).with_name('bsd_program.bzl')
rule_hash=digest(rule)
shutil.copyfile(rule,workspace/'bsd_program.bzl')
identity_rule=Path(__file__).with_name('source_identity.bzl');identity_hash=digest(identity_rule)
shutil.copyfile(identity_rule,workspace/identity_rule.name)
shutil.copyfile(settings['module-lock'],workspace/'MODULE.bazel.lock')
(workspace/'MODULE.bazel').write_text('module(name="bsd_components")\nbazel_dep(name="rules_cc", version="0.2.17")\nbazel_dep(name="platforms", version="1.0.0")\nregister_toolchains("//toolchain:registered")\n')
(workspace/'main.cc').write_text('''#include <string>
#ifdef C_ONLY
#error C flags leaked into C++
#endif
#ifndef CPP_ONLY
#error missing C++ flags
#endif
extern "C" int answer(void);
extern "C" int constructed;
int main() { return std::string("native").size() == 6 && answer() == 7 && constructed == 9 ? 0 : 1; }
''')
(workspace/'function.c').write_text('''#ifndef C_ONLY
#error missing per-source C flag
#endif
#ifdef CPP_ONLY
#error C++ flags leaked into C
#endif
int answer(void) { return C_ONLY; }
''')
(workspace/'constructor.c').write_text('''#if defined(C_ONLY) || defined(CPP_ONLY)
#error unrelated source flags leaked
#endif
int constructed;
__attribute__((constructor)) static void initialize(void) { constructed = 9; }
''')
flags={'main.cc':['-std=c++17','-DCPP_ONLY=1'],'function.c':['-DC_ONLY=7'],'constructor.c':[]}
def buildfile():
 (workspace/'BUILD.bazel').write_text('load("@rules_cc//cc:defs.bzl", "cc_binary")\nload(":bsd_program.bzl", "bsd_program_objects")\n'+'bsd_program_objects(name="objects", srcs='+repr(list(flags))+', position_independent='+repr(args.pic)+', source_order='+repr(list(flags))+', source_flags='+repr(flags)+')\ncc_binary(name="probe", srcs=[":objects"], linkopts=["--driver-mode=g++"], linkstatic=False)\n')
buildfile();commands=[]
def run(label,expected):
 argv=[str(args.bazel),'--batch','--ignore_all_rc_files','--output_user_root='+str(root/'bazel-user-root'),'build','--lockfile_mode=error','--repository_disable_download','--repository_cache='+settings['repository-cache'],'--platforms=//toolchain:native','--host_platform=//toolchain:native','--jobs='+str(os.cpu_count()),'--noexecution_log_sort','--execution_log_json_file='+str(root/(label+'.execution.json')),*['--distdir='+p for p in settings['distdirs']],'//:probe']
 with (root/(label+'.stdout')).open('w') as stdout,(root/(label+'.stderr')).open('w') as stderr:
  result=subprocess.run(['/usr/bin/time','-l',*argv],cwd=workspace,env=dict(os.environ,JAVA_HOME=settings['java-home'],LC_ALL='C',BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1'),stdout=stdout,stderr=stderr)
 commands.append(dict(name=label,exit_status=result.returncode));(root/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');assert result.returncode==0,label
 result=subprocess.run([str(workspace/'bazel-bin/probe')]);assert result.returncode==expected,(label,result.returncode)
run('cold',0)
run('cached',0)
flags['function.c']=['-DC_ONLY=8'];buildfile();run('changed',1)
flags['function.c']=['-DC_ONLY=7'];buildfile();run('restored',0)
decoder=json.JSONDecoder();actions={}
for name, expected_sources in [('cold',{'main.cc','function.c','constructor.c'}),('cached',set()),('changed',{'function.c'}),('restored',{'function.c'})]:
 text=(root/(name+'.execution.json')).read_text();entries=[]
 while text.strip():
  text=text.lstrip();entry,end=decoder.raw_decode(text);text=text[end:];entries.append(entry)
 compiled=[entry for entry in entries if entry.get('mnemonic')=='CppCompile']
 sources=[entry['commandArgs'][entry['commandArgs'].index('-c')+1] for entry in compiled]
 assert len(sources)==len(expected_sources) and set(sources)==expected_sources,(name,sources)
 actions[name]=dict(compilations=len(compiled),links=sum(entry.get('mnemonic')=='CppLink' for entry in entries))
# The final restored parameter file must preserve the declared object order.
params=(workspace/'bazel-bin/probe-0.params').read_text().splitlines()
objects=[arg for arg in params if arg.endswith('.o')]
assert [Path(arg).name for arg in objects]==[name+('.pic.o' if args.pic else '.o') for name in ('main','function','constructor')],objects
assert digest(rule)==rule_hash
assert digest(identity_rule)==identity_hash
(root/'action-audit.json').write_text(json.dumps(dict(status='passed',actions=actions,object_order=objects),indent=2)+'\n')
(root/'receipt.json').write_text(json.dumps(dict(status='passed',scope='native program object primitive mixed-language flag isolation, constructor retention and runtime invalidation; not converted base program',position_independent=args.pic,rule_sha256=rule_hash,actions=actions,input_sha256={str(args.inputs):digest(args.inputs),str(args.bazel):digest(args.bazel),str(Path(__file__)):digest(Path(__file__)),str(rule):rule_hash,str(identity_rule):identity_hash},commands=commands),indent=2)+'\n');print(root/'receipt.json')
