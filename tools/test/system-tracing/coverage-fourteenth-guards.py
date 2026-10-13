#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Guard/errno fault injection for every new USDT header."""
import collections,json,os,subprocess,tempfile
from pathlib import Path
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-fourteenth-validation');T=O/'smoke';T.mkdir(exist_ok=True)
root=Path('/usr/obj/usr/src/amd64.amd64/tmp')
inv=json.loads((S/'tools/test/system-tracing/coverage-fourteenth.json').read_text())
results=[]
def run(cmd,**kw):
 r=subprocess.run([str(a) for a in cmd],capture_output=True,text=True,timeout=30,**kw)
 assert r.returncode==0,(cmd,r.stdout,r.stderr)
 return r
# Compile real trace headers against a fake provider that corrupts errno.
# The fake backend tests wrapper semantics, not live DTrace firing.
providers=collections.defaultdict(list)
for p in inv['probes']:
 if p['kind']=='user':providers[p['provider'].rstrip('*')].append(p)
for provider,ps in providers.items():
 d=T/provider;d.mkdir(exist_ok=True)
 hdr='';body=''
 for p in ps:
  raw=provider.upper()+'_'+p['name'].replace('-','_').upper()
  macro='TRACE_'+provider.upper()+'_'+p['name'].replace('-','__').upper()
  signature=', '.join(t+' a'+str(i) for i,t in enumerate(p['types']))
  hdr+=f'#define {raw}_ENABLED() (active)\nstatic void {raw}({signature}) {{ '+''.join(f'(void)a{i}; ' for i in range(len(p['types'])))+'calls++; errno=EIO; }\n'
  args=', '.join(['++evaluations']+['0']*(len(p['types'])-1))
  body+=f'active=0; calls=0; evaluations=0; errno=EAGAIN; {macro}({args}); assert(calls==0 && evaluations==0 && errno==EAGAIN);\n'
  body+=f'active=1; calls=0; evaluations=0; errno=EAGAIN; {macro}({args}); assert(calls==expected && evaluations==expected && errno==EAGAIN);\n'
 (d/(provider+'_provider.h')).write_text(hdr)
 header=S/Path(ps[0]['source']).parent/(provider+'_trace.h')
 text='#include <assert.h>\n#include <errno.h>\n#include <stdint.h>\n#include <stddef.h>\nstatic int active, calls, evaluations;\n'
 if provider=='fetchio':text+='const unsigned char __bsd_dof_anchor_fetchio_provider __attribute__((visibility("hidden"))) = 0;\n'
 text+=f'#include "{header}"\nint main(void) {{\n#ifdef WITH_COVERAGE_DTRACE\nint expected=1;\n#else\nint expected=0;\n#endif\n'+body+'return 0; }\n'
 c=d/'guard.c';c.write_text(text)
 for mode in ('yes','no'):
  exe=d/('guard-'+mode);cmd=['cc','-Werror','-I'+str(d)]
  if mode=='yes':cmd+=['-DWITH_COVERAGE_DTRACE']
  run(cmd+[c,'-o',exe]);run([exe]);results.append(dict(test='guard/errno',provider=provider,mode=mode,status=0))
(T/'guard-results.json').write_text(json.dumps(results,indent=2)+'\n')
print(len(results),'USDT guard/errno checks passed')
