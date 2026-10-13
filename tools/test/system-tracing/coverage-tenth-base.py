#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Build tenth-round native base programs with and without USDT."""
import concurrent.futures,json,os,subprocess,shlex
from pathlib import Path
S=Path('/usr/src'); O=Path('/usr/obj/5bsd-dtrace-tenth-validation')
SYSROOT='/usr/obj/usr/src/amd64.amd64/tmp'
components=['usr.bin/touch', 'usr.bin/stat', 'usr.sbin/chown', 'usr.bin/mkfifo', 'usr.bin/pathchk', 'usr.bin/du', 'bin/df', 'sbin/sysctl', 'usr.bin/limits', 'usr.bin/killall', 'bin/kill', 'usr.bin/logger', 'usr.sbin/daemon', 'usr.bin/env', 'usr.bin/getconf', 'bin/cpuset', 'bin/timeout', 'bin/realpath', 'bin/sleep', 'usr.bin/mktemp']
results=[]
for component in components:
 for enabled in ('yes','no'):
  out=O/'base'/(component.replace('/','_')+'-'+enabled);out.mkdir(parents=True,exist_ok=True)
  cmd=['make','-C',str(S/component),'-m',str(S/'share/mk'),'-j'+str(os.cpu_count()),'SRCTOP='+str(S),'MAKEOBJDIR='+str(out),'MK_TESTS=no','MK_DTRACE='+enabled,'SYSROOT='+SYSROOT,'CFLAGS_LAST=--sysroot='+SYSROOT,'LDFLAGS_LAST=--sysroot='+SYSROOT,'all']
  with (out/'build.log').open('w') as log:
   log.write(shlex.join(cmd)+'\n');log.flush();r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  results.append(dict(component=component,hooks=enabled,status=r.returncode,command=cmd))
  (O/'base-results.json').write_text(json.dumps(results,indent=2)+'\n')
  print(component,enabled,r.returncode,flush=True)
  if r.returncode:print((out/'build.log').read_text()[-4000:],flush=True)
raise SystemExit(int(any(r['status'] for r in results)))
