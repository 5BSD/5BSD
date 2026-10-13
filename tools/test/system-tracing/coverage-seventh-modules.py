#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
# Prepared native amd64 validation only; see COVERAGE-SEVENTH.
from pathlib import Path
import subprocess,os,json,re,shlex
S=Path('/usr/src');K=Path('/usr/obj/usr/src/amd64.amd64/sys/GENERIC-NODEBUG');O=Path('/usr/obj/5bsd-dtrace-seventh-validation/modules');O.mkdir(parents=True,exist_ok=True)
opts=' '.join(sorted(set(re.findall(r'^#define\s+(\w+)', '\n'.join(p.read_text() for p in K.glob('opt*.h')),re.M))))
results=[]
for module in ['ntsync','mac_do','mac_capability_coalition','netgraph/bluetooth/hci','mac_veriexec','vmm']:
 cwd=K/'modules/usr/src/sys/modules'/module;cwd.mkdir(parents=True,exist_ok=True)
 cmd=['make','-C',str(S/'sys/modules'/module),'-m',str(S/'share/mk'),'-j'+str(os.cpu_count()),'MAKEOBJDIR='+str(cwd),'KERNBUILDDIR='+str(K),'KERN_OPTS='+opts,'all']
 log=O/(module.replace('/','_')+'.log')
 with log.open('w') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
 results.append(dict(module=module,status=r.returncode,command=cmd));print(module,r.returncode,flush=True)
 if r.returncode:print('\n'.join(log.read_text().splitlines()[-15:]),flush=True)
 if module=='vmm' and r.returncode==0:
  flags=shlex.split(subprocess.check_output(cmd[:-1]+['-V','${CFLAGS}'],text=True))
  for enabled in [True,False]:
   compile_cmd=['cc',*flags,'-Werror']
   if not enabled:compile_cmd+=['-include','/usr/obj/5bsd-dtrace-seventh-validation/kernel/nohooks.h']
   compile_cmd+=['-c',str(S/'sys/amd64/vmm/vmm.c'),'-o',str(O/('vmm-'+str(enabled)+'.o'))]
   c=subprocess.run(compile_cmd,cwd=cwd,capture_output=True,text=True)
   (O/('vmm-'+str(enabled)+'.log')).write_text(c.stdout+c.stderr)
   results.append(dict(source='vmm.c',hooks=enabled,status=c.returncode,command=compile_cmd));print('vmm compile',enabled,c.returncode,flush=True)
 (O/'results.json').write_text(json.dumps(results,indent=2)+'\n')

raise SystemExit(int(any(r["status"] != 0 for r in results)))
