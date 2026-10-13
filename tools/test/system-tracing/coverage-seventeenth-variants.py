#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile IPC sources without RACCT and check remaining pressure probe sites."""
from pathlib import Path
import concurrent.futures,importlib.util,json,os,re,subprocess
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-seventeenth-validation');V=O/'variants';V.mkdir(exist_ok=True)
spec=importlib.util.spec_from_file_location('elf',S/'tools/test/system-tracing/coverage-sixth-objects.py');elf=importlib.util.module_from_spec(spec);spec.loader.exec_module(elf)
(V/'noracct.h').write_text('#undef RACCT\n')
expected={'sysv_msg':('sysvmsg__limit',1),'sysv_sem':('sysvsem__limit',2),'sysv_shm':('sysvshm__limit',3)}
rows=[r for r in json.loads((O/'kernel/results.json').read_text()) if Path(r['source']).stem in expected]
def run(row):
 stem=Path(row['source']).stem;hooks=row['name'].endswith('-True');cmd=row['command'].copy();at=cmd.index('-c');cmd[at:at]=['-include',str(V/'noracct.h')];cmd[-1]=str(V/(row['name']+'.o'))
 r=subprocess.run(cmd,cwd=row['cwd'],capture_output=True,text=True);Path(cmd[-1]).with_suffix('.log').write_text(r.stdout+r.stderr);assert r.returncode==0,(row['name'],r.stderr)
 obj=elf.Object(Path(cmd[-1]));name,count=expected[stem];pattern=re.compile(r'(?:^|\.)sdt_sdt___'+name+r'(?:\.[0-9]+)?$');defs=[s for s in obj.symbols if pattern.search(s['name'])]
 assert len(defs)==(count if hooks else 0),(row['name'],len(defs))
 for sym in defs:
  matches=[(patch,target) for probe,patch,target in obj.tracepoints() if probe==(sym['section'],sym['value'])];assert matches
  for (sec,offset),target in matches:assert obj.sections[sec][2]&4 and obj.section_data(sec)[offset:offset+5]==bytes.fromhex('660f1f0400')
 print(row['name'],'RACCT off PASS',flush=True)
 return dict(source=row['source'],hooks=hooks,status=0,remaining_limit_sites=len(defs),command=cmd)
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:results=list(pool.map(run,rows))
(O/'variant-results.json').write_text(json.dumps(results,indent=2)+'\n')
