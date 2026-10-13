#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Isolated behavioral checks; no global settings, outside-process signaling, or system logging."""
from pathlib import Path
import errno,json,os,shutil,socket,stat,subprocess,tempfile
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-tenth-validation');T=O/'smoke';T.mkdir(exist_ok=True)
R=Path('/usr/obj/usr/src/amd64.amd64/tmp');env=os.environ.copy();env['LD_LIBRARY_PATH']=str(R/'lib')+':'+str(R/'usr/lib');env['LC_ALL']='C'
results=[]
def binary(component,mode):return O/'base'/(component.replace('/','_')+'-'+mode)/component.split('/')[-1]
def run(component,args,mode,wd,success=True):
 cmd=[str(binary(component,mode)),*map(str,args)]
 r=subprocess.run(cmd,cwd=wd,env=env,capture_output=True,text=True,timeout=15)
 assert (r.returncode==0)==success,(cmd,r.returncode,r.stdout,r.stderr)
 results.append(dict(component=component,mode=mode,args=list(map(str,args)),status=0,exit=r.returncode))
 return r
for mode in ('yes','no'):
 with tempfile.TemporaryDirectory(dir=T,prefix='behavior-'+mode+'-') as name:
  wd=Path(name);target=wd/'file';target.write_text('fixture\n')
  run('usr.bin/touch',['-t','202001020304',target],mode,wd)
  assert target.stat().st_mtime==1577934240
  run('usr.bin/touch',[wd/'missing'/'file'],mode,wd,False)
  r=run('usr.bin/stat',['-f','%z',target],mode,wd);assert r.stdout=='8\n'
  run('usr.bin/stat',[wd/'absent'],mode,wd,False)
  run('usr.sbin/chown',[str(os.getuid())+':'+str(os.getgid()),target],mode,wd)
  run('usr.sbin/chown',[str(os.getuid()),wd/'absent'],mode,wd,False)
  run('usr.bin/mkfifo',['-m','600','fifo'],mode,wd);assert stat.S_ISFIFO((wd/'fifo').stat().st_mode)
  run('usr.bin/mkfifo',['fifo'],mode,wd,False)
  run('usr.bin/pathchk',[target],mode,wd)
  run('usr.bin/pathchk',['x'*300],mode,wd,False)
  run('usr.bin/du',['-s',wd],mode,wd)
  run('usr.bin/du',[wd/'absent'],mode,wd,False)
  run('bin/df',[wd],mode,wd)
  run('bin/df',[wd/'absent'],mode,wd,False)
  r=run('sbin/sysctl',['-n','hw.ncpu'],mode,wd);assert int(r.stdout)>0
  run('sbin/sysctl',['nonexistent.dtrace.tenth'],mode,wd,False)
  run('usr.bin/limits',['-n','64','/usr/bin/true'],mode,wd)
  # Signal zero checks permission/existence, never delivers a signal.
  run('bin/kill',['-0',os.getpid()],mode,wd)
  run('bin/kill',['-0','2147483647'],mode,wd,False)
  unique='dt10_'+str(os.getpid());childbin=wd/unique;shutil.copy2('/bin/sleep',childbin)
  child=subprocess.Popen([str(childbin),'10'])
  try:
   run('usr.bin/killall',['-0',unique],mode,wd)
   run('usr.bin/killall',['-0','dt10_no_such_process'],mode,wd,False)
   run('bin/cpuset',['-g','-p',child.pid],mode,wd)
  finally:
   child.terminate();child.wait(timeout=5)
  # Only a private loopback receiver, never the system logger or a remote host.
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
   sock.bind(('127.0.0.1',0));sock.settimeout(5)
   run('usr.bin/logger',['-h','127.0.0.1','-P',sock.getsockname()[1],'trace-test'],mode,wd)
   assert b'trace-test' in sock.recv(8192)
  run('usr.bin/env',['-C',wd,'/usr/bin/true'],mode,wd)
  run('usr.bin/env',['-C',wd/'absent','/usr/bin/true'],mode,wd,False)
  r=run('usr.bin/getconf',['ARG_MAX'],mode,wd);assert int(r.stdout)>0
  # Timeout affects only the child it creates, including both foreground/reaper modes.
  run('bin/timeout',['--foreground','.05','/bin/sleep','1'],mode,wd,False)
  run('bin/timeout',['.05','/bin/sleep','1'],mode,wd,False)
  r=run('bin/realpath',[target],mode,wd);assert r.stdout.strip()==str(target)
  run('bin/realpath',[wd/'absent'/'file'],mode,wd,False)
  run('bin/sleep',['.001'],mode,wd)
  r=run('usr.bin/mktemp',['test.XXXXXXXX'],mode,wd);assert (wd/r.stdout.strip()).is_file()
  r=run('usr.bin/mktemp',['-d','dir.XXXXXXXX'],mode,wd);assert (wd/r.stdout.strip()).is_dir()
  run('usr.bin/mktemp',['absent/test.XXXXXXXX'],mode,wd,False)
  # Relink real daemon objects, replacing only daemon(3) to stay foreground.
  stub=T/'foreground.o'
  cmd=['cc','--sysroot='+str(R),'-Werror','-fPIE','-c',str(S/'tools/test/system-tracing/coverage-tenth-foreground.c'),'-o',str(stub)]
  subprocess.run(cmd,check=True,capture_output=True)
  out=binary('usr.sbin/daemon',mode).parent;exe=T/('daemon-'+mode+'-foreground')
  objects=[out/'daemon.pieo',stub]
  if mode=='yes':objects.append(out/'daemonwait_provider.pieo')
  cmd=['cc','--sysroot='+str(R),'-pie',*map(str,objects),'-Wl,--wrap=daemon','-lutil','-o',str(exe)]
  subprocess.run(cmd,check=True,capture_output=True)
  r=subprocess.run([str(exe),'-P',str(wd/'supervisor.pid'),'/usr/bin/touch',str(wd/'child.completed')],env=env,cwd=wd,capture_output=True,text=True,timeout=10)
  # daemon_terminate deliberately exits 1 even after normal child exit.
  assert r.returncode==1 and 'foreground fixture' in r.stderr,(r.returncode,r.stdout,r.stderr)
  assert not (wd/'supervisor.pid').exists() and (wd/'child.completed').exists()
  results.append(dict(component='usr.sbin/daemon',mode=mode,status=0,test='real supervisor, wrapped daemon(3), short-lived child'))
(T/'behavior-results.json').write_text(json.dumps(results,indent=2)+'\n')
print(len(results),'isolated behavior checks passed')
