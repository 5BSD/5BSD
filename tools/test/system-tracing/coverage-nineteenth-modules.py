#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Build requested native modules in the prepared kernel object tree."""
from pathlib import Path
import subprocess,os,json,re,shlex
S=Path('/usr/src');K=Path('/usr/obj/usr/src/amd64.amd64/sys/GENERIC-NODEBUG');O=Path('/usr/obj/5bsd-dtrace-nineteenth-validation/modules');O.mkdir(parents=True,exist_ok=True)
opts=' '.join(sorted(set(re.findall(r'^#define\s+(\w+)', '\n'.join(p.read_text() for p in K.glob('opt*.h')),re.M))))
modules=json.loads((S/'tools/test/system-tracing/coverage-nineteenth-build.json').read_text())
results=[]
for module in modules:
 cwd=K/'modules/usr/src/sys/modules'/module;cwd.mkdir(parents=True,exist_ok=True)
 cmd=['make','-C',str(S/'sys/modules'/module),'-m',str(S/'share/mk'),'-j'+str(os.cpu_count()),'MAKEOBJDIR='+str(cwd),'KERNBUILDDIR='+str(K),'KERN_OPTS='+opts,'all']
 log=O/(module.replace('/','_')+'.log')
 with log.open('w') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
 results.append(dict(module=module,status=r.returncode,command=cmd));print(module,r.returncode,flush=True)
 if r.returncode:print('\n'.join(log.read_text().splitlines()[-18:]),flush=True)
 (O/'results.json').write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(int(any(r['status'] for r in results)))
