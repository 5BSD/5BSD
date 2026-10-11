#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess,os,json,socket,threading,signal,resource
W=Path('/usr/obj/5bsd-dtrace-third-validation/userspace');D=W/'smoke';S=Path(__file__).resolve().parent;results=[]
def run(label,cmd,env=None,compat=False):
 def setup():
  resource.setrlimit(resource.RLIMIT_CORE,(0,0))
  if compat:signal.signal(signal.SIGSYS,signal.SIG_IGN)
 r=subprocess.run(list(map(str,cmd)),env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30,preexec_fn=setup,cwd=D)
 blocked=label.startswith('rtld-') and 'host-compat' not in label and r.returncode==-signal.SIGSYS
 (D/(label+'.log')).write_text(r.stdout);print(label,'PASS' if not r.returncode else 'BLOCKED (host syscall)' if blocked else 'FAIL',flush=True);results.append(dict(name=label,status=r.returncode,host_syscall_limitation=blocked,command=list(map(str,cmd))));return r.returncode==0
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0));udp.settimeout(30)
def dns():
 for _ in range(2):
  b,addr=udp.recvfrom(4096);b=bytearray(b);b[2]|=0x80;udp.sendto(b,addr)
threading.Thread(target=dns,daemon=True).start()
conf=D/'pam-deny.conf';conf.write_text('auth required pam_deny.so\n')
for mode in ['hooks','nohooks']:
 libc=W/('lib_libc-'+mode)/'obj';pam=W/('lib_libpam_libpam-'+mode)/'obj';rtld=W/('libexec_rtld-elf-'+mode)/'obj/ld-elf.so.1'
 env=dict(os.environ);env['LD_LIBRARY_PATH']=str(libc)+':/usr/obj/usr/src/amd64.amd64/tmp/lib'
 exe=D/('resolve-'+mode)
 if run('compile-resolve-'+mode,['cc',S/'resolve.c','-o',exe]):run('resolve-'+mode,[exe,str(udp.getsockname()[1])],env)
 exe=D/('pam-'+mode)
 if run('compile-pam-'+mode,['cc',S/'pam.c','-o',exe,'-L'+str(pam),'-Wl,-rpath,'+str(pam),'-lpam']):run('pam-'+mode,[exe,conf])
 exe=D/('rtld-'+mode);so=D/('initializer-'+mode+'.so')
 if run('compile-initializer-'+mode,['cc','-shared','-fPIC',S/'initializer.c','-o',so]) and run('compile-rtld-'+mode,['cc',S/'rtld.c','-o',exe]):
  run('rtld-startup-'+mode,[rtld,'/usr/bin/true'])
  run('rtld-dlopen-'+mode,[rtld,exe,so])
  run('rtld-startup-host-compat-'+mode,[rtld,'/usr/bin/true'],compat=True)
  run('rtld-dlopen-host-compat-'+mode,[rtld,exe,so],compat=True)
udp.close();(D/'core-results.json').write_text(json.dumps(results,indent=2)+'\n')

raise SystemExit(int(any(r["status"] and not r["host_syscall_limitation"] for r in results)))
