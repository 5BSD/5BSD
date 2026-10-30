#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify SDK package relocation and external Bzlmod toolchain resolution."""
import argparse,json,os,shutil,subprocess
from pathlib import Path
from libmd_environment import digest
p=argparse.ArgumentParser(description=__doc__)
for key in ('inputs','bazel','output'):p.add_argument('--'+key,type=Path,required=True)
a=p.parse_args();out=a.output.resolve()
if out.exists() or not out.is_relative_to('/usr/obj') or out==Path('/usr/obj'):p.error('fresh /usr/obj output required')
settings=json.loads(a.inputs.read_text());sdk=Path(settings['toolchain-workspace'])
receipt_path=Path(settings['toolchain-receipt']);receipt=json.loads(receipt_path.read_text())
# This test deliberately evaluates a new rule against an immutable prepared SDK.
# Verify every snapshot byte; its historical source files need not still match.
for name,value in receipt['snapshot'].items():
 path=Path(name)
 if path.is_absolute() or '..' in path.parts:raise ValueError('invalid SDK snapshot path')
 assert digest(sdk/path)==value,name
rule=Path(__file__).with_name('native_cc_toolchain_config.bzl')
inputs={str(path.resolve()):digest(path) for path in [a.inputs,a.bazel,receipt_path,rule,Path(__file__)]}
out.mkdir();commands=[]
deps='bazel_dep(name="rules_cc", version="0.2.17")\nbazel_dep(name="platforms", version="1.0.0")\n'
for mode in ('nested','external'):
 w=out/mode;w.mkdir();tc=(w/'sdk/native' if mode=='nested' else out/'sdk-repository/sdk/native')
 shutil.copytree(sdk/'toolchain',tc,symlinks=True)
 shutil.copyfile(rule,tc/'cc_toolchain_config.bzl')
 prefix='//sdk/native' if mode=='nested' else '@bsd_sdk//sdk/native'
 module='module(name="relocation_probe")\n'+deps
 if mode=='external':
  repo=out/'sdk-repository';(repo/'MODULE.bazel').write_text('module(name="bsd_sdk",version="0.0.0")\n'+deps)
  module+='bazel_dep(name="bsd_sdk",version="0.0.0")\nlocal_path_override(module_name="bsd_sdk",path="../sdk-repository")\n'
 module+='register_toolchains("'+prefix+':registered")\n'
 (w/'MODULE.bazel').write_text(module);shutil.copyfile(settings['module-lock'],w/'MODULE.bazel.lock')
 (w/'probe.c').write_text('#include <stdio.h>\nint main(void) { return puts("relocated SDK") < 0; }\n')
 (w/'BUILD.bazel').write_text('load("@rules_cc//cc:defs.bzl", "cc_test")\ncc_test(name="probe",srcs=["probe.c"],size="small")\n')
 argv=[str(a.bazel),'--batch','--ignore_all_rc_files','--output_user_root='+str(out/(mode+'-bazel-root')),'test','--lockfile_mode=update','--repository_disable_download','--repository_cache='+settings['repository-cache'],'--platforms='+prefix+':native','--host_platform='+prefix+':native','--jobs='+str(os.cpu_count()),'--test_output=errors',*['--distdir='+d for d in settings['distdirs']],'//:probe']
 with (out/(mode+'.stdout')).open('w') as stdout,(out/(mode+'.stderr')).open('w') as stderr:
  r=subprocess.run(['/usr/bin/time','-l',*argv],cwd=w,env=dict(os.environ,JAVA_HOME=settings['java-home'],LC_ALL='C',BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1'),stdout=stdout,stderr=stderr)
 commands.append(dict(mode=mode,argv=argv,exit_status=r.returncode));(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
 assert r.returncode==0,mode
for path,value in inputs.items():assert digest(Path(path))==value,path
(out/'receipt.json').write_text(json.dumps(dict(status='passed',scope='native C compile/link/test using nested and external repository SDK packages; prepared SDK, not bootstrap or cross compilation',input_sha256=inputs,sdk_snapshot=receipt['snapshot'],commands=commands),indent=2)+'\n')
print(out/'receipt.json')
