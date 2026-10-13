#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess,json,os
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-twentieth-validation'); R=O/'tests';R.mkdir(exist_ok=True)
results=[]
def run(cmd,tag,cwd=R,env=None):
 r=subprocess.run(cmd,cwd=cwd,env=env,capture_output=True,text=True);(R/(tag+'.log')).write_text(r.stdout+r.stderr);results.append(dict(test=tag,status=r.returncode));print(tag,r.returncode,flush=True)
 if r.returncode: print((r.stdout+r.stderr)[-1500:])
 return r
for mode in ('yes','no'):
 base=O/'base'/('lib_libservice-'+mode);lib=O/'base'/('lib_libchannel-'+mode)
 exe=R/('runtime-'+mode)
 cmd=['cc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-I'+str(S/'lib/libservice'),'-I'+str(S/'lib/libchannel'),'-I'+str(S/'sys'),str(S/'lib/libservice/tests/runtime_test.c'),'-L'+str(base),'-Wl,-rpath,'+str(base),'-lservice','-lprivateatf-c','-lpthread','-o',str(exe)]
 if run(cmd,'runtime-build-'+mode).returncode==0:
  for case in ('retry_and_health','lease_ownership','drain_deadline','budget_scope'):
   run([str(exe),'-r',str(R/(case+'-'+mode+'.result')),case],case+'-'+mode)
 zsh=O/'base'/('bin_zsh-'+mode)/'zsh';work=R/('zsh-'+mode)/'Test';work.mkdir(parents=True,exist_ok=True)
 (work.parent/'Src').mkdir(exist_ok=True)
 link=work.parent/'Src/zsh'
 if not link.exists(): link.symlink_to(zsh)
 env=dict(os.environ,ZTST_exe=str(zsh),ZTST_srcdir=str(S/'contrib/zsh/Test'))
 for name in ('A01grammar','A05execution','A06assign'):
  p=S/'contrib/zsh/Test'/(name+'.ztst')
  if p.exists():run([str(zsh),'-f',str(S/'contrib/zsh/Test/ztst.zsh'),str(p)],name+'-'+mode,cwd=work,env=env)
profiles=json.loads((S/'tools/test/system-tracing/coverage-twentieth.json').read_text())['profiles'];installed=subprocess.check_output(['make','-C',str(S/'cddl/usr.sbin/bsdinstruments'),'-m',str(S/'share/mk'),'-V','PROFILES'],text=True).split()
for name in profiles:
 assert name+'.d' in installed
 for filtered in (False,True):
  cmd=['bsdinstruments','generate','-f',str(S/'cddl/usr.sbin/bsdinstruments/profiles'/(name+'.d'))]
  if filtered:cmd+=['--pid','42','--duration','1']
  s=subprocess.check_output(cmd,text=True);assert '@bsdinstruments-' not in s
  p=R/(name+str(filtered)+'.d');p.write_text(s);run(['dtrace','-e','-Z','-s',str(p)],name+str(filtered))
(O/'test-results.json').write_text(json.dumps(results,indent=2)+'\n')
assert all(r['status']==0 for r in results)
