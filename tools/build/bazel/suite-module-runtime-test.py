#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify declared ATF module staging, loader identity and dynamic dependency changes."""
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
for name in ('bsd_program.bzl','source_identity.bzl','bsd_kyua.bzl','bsd_kyua_metadata.bzl','elf-runtime-check.py','libmd_environment.py'):
 source=Path(__file__).with_name(name);inputs[str(source)]=digest(source);shutil.copyfile(source,w/name)
shutil.copyfile(config['module-lock'],w/'MODULE.bazel.lock')
(w/'MODULE.bazel').write_text('module(name="bsd_components")\nbazel_dep(name="rules_cc", version="0.2.17")\nbazel_dep(name="platforms", version="1.0.0")\nregister_toolchains("//toolchain:registered")\n')

(w/'dep.c').write_text('int value(void) { return 7; }\n')
(w/'module.c').write_text('int value(void); static int result; __attribute__((constructor)) static void init(void) { result=value(); } int answer(void) { return result; }\n')
(w/'probe.c').write_text(r'''#include <atf-c.h>
#include <dlfcn.h>
#include <stdio.h>
ATF_TC(module);
ATF_TC_HEAD(module, tc) { atf_tc_set_md_var(tc, "descr", "Load a staged shared module and its dependency"); }
ATF_TC_BODY(module, tc) {
 char path[4096];
 ATF_REQUIRE(snprintf(path,sizeof(path),"%s/module.so",atf_tc_get_config_var(tc,"srcdir")) < (int)sizeof(path));
 void *handle=dlopen(path,RTLD_NOW|RTLD_LOCAL);
 ATF_REQUIRE_MSG(handle!=NULL,"dlopen failed: %s",dlerror());
 int (*answer)(void)=(int (*)(void))dlsym(handle,"answer");
 ATF_REQUIRE(answer!=NULL);
 ATF_REQUIRE_EQ(answer(),7);
 ATF_REQUIRE_EQ(dlclose(handle),0);
}
ATF_TP_ADD_TCS(tp) { ATF_TP_ADD_TC(tp,module); return atf_no_error(); }
''')
def rule(kind,**attrs):return kind+'('+', '.join(k+'='+repr(v) for k,v in attrs.items())+')'
lines=['load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")','load(":bsd_program.bzl", "bsd_program_objects")','load(":bsd_kyua.bzl", "bsd_kyua_test")']
lines += [rule('bsd_program_objects',name='module_objects',srcs=['module.c'],source_order=['module.c'],source_flags={'module.c':['-fpic']},position_independent=True),
 rule('cc_binary',name='libfixturedep.so',srcs=['dep.c'],linkshared=True,linkopts=['-Wl,-soname,libfixturedep.so']),
 rule('cc_import',name='dep',shared_library=':libfixturedep.so'),
 rule('cc_binary',name='module.so',srcs=[':module_objects'],deps=[':dep'],linkshared=True,linkopts=['-Wl,-soname,module.so','-Wl,--disable-new-dtags','-Wl,-rpath,$$ORIGIN'],features=['bsd_test_runtime_paths']),
 rule('cc_binary',name='probe',srcs=['probe.c'],linkopts=['-lprivateatf-c','-Wl,--disable-new-dtags','-Wl,-rpath,$$ORIGIN'],features=['bsd_test_runtime_paths'])]
libraries={'//toolchain:sysroot/usr/lib/libprivateatf-c.so.1':'libprivateatf-c.so.1','//toolchain:sysroot/lib/libc.so.7':'libc.so.7','//toolchain:sysroot/lib/libsys.so.7':'libsys.so.7'}
lines += [rule('bsd_kyua_test',name='suite',interface='atf',program=':probe',kyua='//toolchain:extra_kyua',runtime=['//toolchain:extra_kyua_runtime','//toolchain:python_stdlib',':libmd_environment.py'],python='//toolchain:extra_python',python_home='//toolchain:python-home/runtime.json',runtime_checker=':elf-runtime-check.py',runtime_libraries=libraries,suite_files={':module.so':'module.so',':libfixturedep.so':'libfixturedep.so'},module_dependencies={'module.so':['libfixturedep.so','libc.so.7','libsys.so.7']},clean_environment=True,size='small')]
(w/'BUILD.bazel').write_text('\n'.join(lines)+'\n')
commands=[];counts={};output_hashes={}
def rows(path):
 text=path.read_text();decoder=json.JSONDecoder();offset=0
 while offset<len(text):
  while offset<len(text) and text[offset].isspace():offset+=1
  if offset==len(text):return
  row,offset=decoder.raw_decode(text,offset);yield row

def run(name,expected):
 argv=[str(a.bazel),'--batch','--ignore_all_rc_files','--output_user_root='+str(out/'bazel-root'),'test','--lockfile_mode=error','--repository_disable_download','--repository_cache='+config['repository-cache'],'--platforms=//toolchain:native','--host_platform=//toolchain:native','--jobs='+str(os.cpu_count()),'--test_output=errors','--noexecution_log_sort','--execution_log_json_file='+str(out/(name+'.execution.json')),*['--distdir='+d for d in config['distdirs']],'//:suite']
 with (out/(name+'.stdout')).open('w') as stdout,(out/(name+'.stderr')).open('w') as stderr:
  result=subprocess.run(['/usr/bin/time','-l',*argv],cwd=w,env=dict(os.environ,JAVA_HOME=config['java-home'],LC_ALL='C',BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1'),stdout=stdout,stderr=stderr)
 commands.append(dict(name=name,argv=argv,exit_status=result.returncode));(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
 assert result.returncode==expected,(name,result.returncode)
 test=w/'bazel-testlogs/suite';shutil.copytree(test/'test.outputs',out/(name+'.outputs'));shutil.copyfile(test/'test.log',out/(name+'.test.log'))
 for directory in ['runtime','module-runtime-module.so']:
  receipt=json.loads((out/(name+'.outputs')/directory/'receipt.json').read_text());assert receipt['status']=='passed'
  if directory.startswith('module-'):assert receipt['execution_mode']=='trace-only'
  for record in receipt['libraries'].values():assert digest(Path(record['artifact']))==record['sha256']
 actions=list(rows(out/(name+'.execution.json')));counts[name]=dict(collections.Counter(r.get('mnemonic') for r in actions))
 output_hashes[name]={name:digest(w/'bazel-bin'/name) for name in ['probe','module.so','libfixturedep.so']}
 if name=='cached':assert not actions,counts[name]
 if name=='changed':
  compiled=[r for r in actions if r.get('mnemonic')=='CppCompile'];assert len(compiled)==1 and compiled[0]['targetLabel']=='//:libfixturedep.so'
  assert 'failed:' in (out/(name+'.test.log')).read_text()
run('cold',0);run('cached',0)
try:
 (w/'dep.c').write_text('int value(void) { return 8; }\n');run('changed',3)
finally:
 (w/'dep.c').write_text('int value(void) { return 7; }\n')
run('restored',0)
assert output_hashes['cold']==output_hashes['restored']
for path,value in inputs.items():assert digest(Path(path))==value,path
(out/'receipt.json').write_text(json.dumps(dict(status='passed',scope='native synthetic ATF module/dependency suite, strict loader identity, constructor behavior and incremental invalidation; SDK libraries are explicit runtime inputs, not newly converted libraries',actions=counts,input_sha256=inputs,commands=commands),indent=2)+'\n');print(out/'receipt.json')
