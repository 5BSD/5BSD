#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check FreeBSD SDT forwarding and no argument evaluation on other backends."""
from pathlib import Path
import json,subprocess
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-twelfth-validation');T=O/'guards';T.mkdir(exist_ok=True)
results=[]
for mode in ['kernel','user','foreign-kernel']:
 source='#include <assert.h>\nstatic int calls, evaluations;\n'
 if mode!='user':source+='#define _KERNEL 1\n'
 if mode=='foreign-kernel':source+='#undef __FreeBSD__\n'
 for count in range(1,5):
  args=['name']
  for n in range(count):args+=['t'+str(n),'a'+str(n)]
  source+='#define DTRACE_PROBE'+str(count)+'('+','.join(args)+') do { calls++; '+''.join('(void)(a'+str(n)+'); ' for n in range(count))+'} while (0)\n'
 source+='#include "'+str(S/'sys/contrib/openzfs/include/sys/trace_bsd.h')+'"\nint main(void) {\n'
 for count in range(1,5):source+='ZFS_BSD_PROBE'+str(count)+'(fixture, '+', '.join(['int, ++evaluations']*count)+');\n'
 source+='assert(calls=='+('4' if mode=='kernel' else '0')+' && evaluations=='+('10' if mode=='kernel' else '0')+'); return 0; }\n'
 c=T/(mode+'.c');c.write_text(source);exe=T/mode
 subprocess.run(['cc','-Werror',str(c),'-o',str(exe)],check=True,capture_output=True)
 subprocess.run([str(exe)],check=True,capture_output=True)
 results.append(dict(mode=mode,status=0))
(O/'guard-results.json').write_text(json.dumps(results,indent=2)+'\n');print('3 backend guard checks passed')
