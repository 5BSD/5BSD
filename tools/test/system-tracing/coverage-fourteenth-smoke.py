#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Isolated CLI behavior checks; kenv/chroot use test-only syscall wrappers."""
from pathlib import Path
import json,os,shutil,subprocess,tempfile
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-fourteenth-validation');T=O/'smoke';T.mkdir(exist_ok=True)
R=Path('/usr/obj/usr/src/amd64.amd64/tmp');env=os.environ.copy();env['LD_LIBRARY_PATH']=str(R/'lib')+':'+str(R/'usr/lib');env['LC_ALL']='C'
results=[]
def binary(c,mode,name=None):return O/'base'/(c.replace('/','_')+'-'+mode)/(name or c.split('/')[-1])
def run(c,args,mode,wd,success=True,input=None,exe=None,extra=None):
 cmd=[str(exe or binary(c,mode)),*map(str,args)];e=env.copy();e.update(extra or {})
 r=subprocess.run(cmd,cwd=wd,env=e,input=input,capture_output=True,timeout=15)
 assert (r.returncode==0)==success,(cmd,r.returncode,r.stdout,r.stderr)
 results.append(dict(component=c,mode=mode,args=list(map(str,args)),status=0,exit=r.returncode))
 return r
stub=T/'syscall-stubs.o'
subprocess.run(['cc','--sysroot='+str(R),'-Werror','-fPIE','-c',str(S/'tools/test/system-tracing/coverage-fourteenth-stubs.c'),'-o',str(stub)],check=True,capture_output=True)
for mode in ('yes','no'):
 with tempfile.TemporaryDirectory(dir=T,prefix='behavior-'+mode+'-') as name:
  wd=Path(name);target=wd/'file';data=b'one\ntwo\nthree\n';target.write_bytes(data)
  r=run('bin/cat',[target],mode,wd);assert r.stdout==data
  run('bin/cat',[wd/'absent'],mode,wd,False)
  r=run('usr.bin/tee',['tee.out'],mode,wd,input=data);assert r.stdout==data and (wd/'tee.out').read_bytes()==data
  run('usr.bin/tee',['absent/out'],mode,wd,False,input=data)
  run('usr.bin/split',['-b','4',target,'part.'],mode,wd);assert b''.join(p.read_bytes() for p in sorted(wd.glob('part.*')))==data
  run('usr.bin/split',['-b','4',target,'absent/part.'],mode,wd,False)
  r=run('usr.bin/wc',['-l',target],mode,wd);assert int(r.stdout.split()[0])==3
  run('usr.bin/wc',[wd/'absent'],mode,wd,False)
  r=run('usr.bin/tail',['-n','1',target],mode,wd);assert r.stdout==b'three\n'
  run('usr.bin/tail',[wd/'absent'],mode,wd,False)
  run('usr.bin/fsync',[target],mode,wd)
  run('usr.bin/fsync',[wd/'absent'],mode,wd,False)
  for args in ([],['-o','1'],['-o','2'],['-o','3']):
   r=run('usr.bin/cksum',[*args,target],mode,wd)
   ref=subprocess.run(['/usr/bin/cksum',*args,str(target)],capture_output=True,check=True)
   assert r.stdout==ref.stdout,(args,r.stdout,ref.stdout)
  run('usr.bin/cksum',[wd/'absent'],mode,wd,False)
  run('bin/getfacl',[target],mode,wd)
  run('bin/getfacl',[wd/'absent'],mode,wd,False)
  run('bin/setfacl',['-b',target],mode,wd)
  run('bin/setfacl',['-b',wd/'absent'],mode,wd,False)
  # Extended attributes are restricted to our private file.
  d='usr.sbin/extattr';real=binary(d,mode,'rmextattr');aliases={}
  for name in ['rmextattr','getextattr','setextattr','lsextattr']:
   alias=wd/name;alias.symlink_to(real);aliases[name]=alias
  run(d,['user','trace_fixture','value',target],mode,wd,exe=aliases['setextattr'])
  r=run(d,['-qq','user','trace_fixture',target],mode,wd,exe=aliases['getextattr']);assert r.stdout==b'value'
  r=run(d,['user',target],mode,wd,exe=aliases['lsextattr']);assert b'trace_fixture' in r.stdout
  run(d,['user','trace_fixture',target],mode,wd,exe=aliases['rmextattr'])
  run(d,['user','trace_fixture',target],mode,wd,False,exe=aliases['getextattr'])
  run(d,['user','trace_fixture',target],mode,wd,False,exe=aliases['rmextattr'])
  run(d,['-h','user','trace_link_fixture','value',target],mode,wd,exe=aliases['setextattr'])
  r=run(d,['-h','-qq','user','trace_link_fixture',target],mode,wd,exe=aliases['getextattr']);assert r.stdout==b'value'
  r=run(d,['-h','user',target],mode,wd,exe=aliases['lsextattr']);assert b'trace_link_fixture' in r.stdout
  run(d,['-h','user','trace_link_fixture',target],mode,wd,exe=aliases['rmextattr'])
  run('sbin/kldstat',[],mode,wd)
  run('sbin/kldstat',['-i','2147483647'],mode,wd,False)
  run('usr.bin/procstat',['-b',str(os.getpid())],mode,wd)
  run('usr.bin/vmstat',[],mode,wd)
  # Wait only on a child created for this test, with a bounded timeout.
  child=subprocess.Popen(['/bin/sleep','.2'])
  try:run('bin/pwait',['-t','2',child.pid],mode,wd)
  finally:child.wait(timeout=3)
  child=subprocess.Popen(['/bin/sleep','3'])
  try:run('bin/pwait',['-t','.05',child.pid],mode,wd,False)
  finally:child.terminate();child.wait(timeout=3)
  elf=wd/'elf';shutil.copy2('/usr/bin/true',elf);elf.chmod(0o700)
  run('usr.bin/brandelf',[elf],mode,wd)
  run('usr.bin/brandelf',['-t','FreeBSD',elf],mode,wd)
  run('usr.bin/brandelf',[target],mode,wd,False)
  for c,p,fn,args in [('bin/kenv','envquery','kenv',['trace_fixture']),('usr.sbin/chroot','rootchange','chroot',[wd,'/usr/bin/true'])]:
   out=binary(c,mode).parent;exe=T/(fn+'-'+mode+'-stubbed');objects=[out/(fn+'.pieo'),stub]
   if mode=='yes':objects.append(out/(p+'_provider.pieo'))
   cmd=['cc','--sysroot='+str(R),'-pie',*map(str,objects),'-Wl,--wrap='+fn,'-o',str(exe)]
   subprocess.run(cmd,check=True,capture_output=True)
   run(c,args,mode,wd,exe=exe)
   run(c,args,mode,wd,False,exe=exe,extra={'DTRACE_TEST_FAIL':'1'})
   if fn=='kenv':
    for options in [[],['trace_fixture=value'],['-u','trace_fixture']]:
     run(c,options,mode,wd,exe=exe)
     run(c,options,mode,wd,False,exe=exe,extra={'DTRACE_TEST_FAIL':'1'})
(T/'behavior-results.json').write_text(json.dumps(results,indent=2)+'\n')
print(len(results),'isolated CLI behavior checks passed')
