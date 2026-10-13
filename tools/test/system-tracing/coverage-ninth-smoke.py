#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise real utility objects with module/sync/flag syscalls replaced at link time."""
from pathlib import Path
import errno,json,os,subprocess,tempfile
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-ninth-validation');T=O/'smoke';T.mkdir(exist_ok=True)
R=Path('/usr/obj/usr/src/amd64.amd64/tmp');env=os.environ.copy();env['LD_LIBRARY_PATH']=str(R/'lib')+':'+str(R/'usr/lib')
results=[]
def checked(command,**kw):
 r=subprocess.run([str(x) for x in command],capture_output=True,text=True,timeout=30,**kw)
 assert r.returncode==0,(command,r.stdout,r.stderr)
 return r
stub=T/'syscall-stubs.o'
checked(['cc','--sysroot='+str(R),'-Wall','-Wextra','-Werror','-fPIE','-c',S/'tools/test/system-tracing/coverage-ninth-syscall-stubs.c','-o',stub])
for mode in ('yes','no'):
 for component,name,provider,symbol,operation,args in [
  ('sbin_kldload','kldload','moduleload','kldload','load',['/nonexistent/dtrace-probe-test.ko']),
  ('sbin_kldunload','kldunload','moduleunload','kldunloadf','unload',['-i','4321']),
  ('bin_sync','sync','flushall','sync','sync',[]),
  ('bin_chflags','chflags','fileflags','chflagsat','flags',['nodump','target'])]:
  out=O/'base'/(component+'-'+mode);exe=T/(name+'-'+mode+'-mock')
  objects=[out/(name+'.pieo')]
  if mode=='yes':objects+=[out/(provider+'_provider.pieo')]
  checked(['cc','--sysroot='+str(R),'-pie',*objects,stub,'-Wl,--wrap='+symbol,'-o',exe])
  with tempfile.TemporaryDirectory(dir=T,prefix=name+'-') as wd:
   (Path(wd)/'target').write_text('fixture')
   errors=(0,) if name=='sync' else (0,errno.EACCES)
   for error in errors:
    e=env.copy();e['DTRACE_TEST_ERRNO']=str(error)
    r=subprocess.run([str(exe),*args],env=e,cwd=wd,capture_output=True,text=True,timeout=10)
    assert (r.returncode==0)==(error==0),(name,mode,error,r.stdout,r.stderr)
    assert 'intercepted '+operation in r.stdout,(name,'syscall wrapper not reached',r.stdout,r.stderr)
    if error:assert os.strerror(error) in r.stderr,(name,r.stderr)
    results.append(dict(test='intercepted '+operation,mode=mode,errno=error,status=0))
   if name=='kldload':
    e=env.copy();e['DTRACE_TEST_ERRNO']=str(errno.EEXIST)
    r=checked([exe,'-n',*args],env=e,cwd=wd);assert 'intercepted load' in r.stdout
    results.append(dict(test='already loaded -n',mode=mode,status=0))
(T/'behavior-results.json').write_text(json.dumps(results,indent=2)+'\n')
print(len(results),'utility success/error checks passed; no module loading, unloading, or system sync')
