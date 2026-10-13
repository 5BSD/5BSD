#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile socket allocation failure branches under optional MAC/helper hooks."""
from pathlib import Path
import concurrent.futures,importlib.util,json,os,re,subprocess
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-eighteenth-validation');V=O/'variants';V.mkdir(exist_ok=True)
spec=importlib.util.spec_from_file_location('elf',S/'tools/test/system-tracing/coverage-sixth-objects.py');elf=importlib.util.module_from_spec(spec);spec.loader.exec_module(elf)
variants={'no-mac':('#undef MAC\n#undef SOCKET_HHOOK\n',2),'socket-hhook':('#define SOCKET_HHOOK 1\n',4)}
for name,(header,count) in variants.items():(V/(name+'.h')).write_text(header)
rows=[r for r in json.loads((O/'kernel/results.json').read_text()) if r['source']=='sys/kern/uipc_socket.c']
def run(job):
 row,name=job;hooks=row['name'].endswith('-True');cmd=row['command'].copy();at=cmd.index('-c');cmd[at:at]=['-include',str(V/(name+'.h'))];cmd[-1]=str(V/(name+'-'+str(hooks)+'.o'))
 r=subprocess.run(cmd,cwd=row['cwd'],capture_output=True,text=True);Path(cmd[-1]).with_suffix('.log').write_text(r.stdout+r.stderr);assert r.returncode==0,(name,hooks,r.stderr)
 obj=elf.Object(Path(cmd[-1]));pattern=re.compile(r'(?:^|\.)sdt_sdt___socket__alloc__failure(?:\.[0-9]+)?$');defs=[s for s in obj.symbols if pattern.search(s['name'])]
 assert len(defs)==(variants[name][1] if hooks else 0),(name,hooks,len(defs))
 for sym in defs:
  matches=[patch for probe,patch,target in obj.tracepoints() if probe==(sym['section'],sym['value'])];assert matches
  for sec,offset in matches:assert obj.sections[sec][2]&4 and obj.section_data(sec)[offset:offset+5]==bytes.fromhex('660f1f0400')
 print(name,hooks,'PASS',flush=True)
 return dict(variant=name,hooks=hooks,status=0,allocation_failure_sites=len(defs),command=cmd)
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:results=list(pool.map(run,[(r,n) for r in rows for n in variants]))
(O/'variant-results.json').write_text(json.dumps(results,indent=2)+'\n')
