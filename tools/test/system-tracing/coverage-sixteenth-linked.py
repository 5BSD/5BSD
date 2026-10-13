#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Verify this round's contracts survive real module linking at executable NOPs."""
from pathlib import Path
import importlib.util,json,re,subprocess
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-sixteenth-validation')
spec=importlib.util.spec_from_file_location('elf',S/'tools/test/system-tracing/coverage-sixth-objects.py');elf=importlib.util.module_from_spec(spec);spec.loader.exec_module(elf)
inv=json.loads((S/'tools/test/system-tracing/coverage-sixteenth.json').read_text())
mods=json.loads((S/'tools/test/system-tracing/coverage-sixteenth-build.json').read_text())
rows=json.loads((O/'modules/results.json').read_text());results=[]
for row in rows:
 assert row['status']==0,row
 mod=row['module'];cwd=Path(next(a.split('=',1)[1] for a in row['command'] if a.startswith('MAKEOBJDIR=')))
 name=subprocess.check_output(row['command'][:-1]+['-V','${KMOD}'],text=True).strip();path=cwd/(name+'.ko')
 obj=elf.Object(path);sites=obj.tracepoints();wanted=[p for p in inv['probes'] if any(f in mods[mod] for f in [p['source'],*p.get('additional_sources',[])])]
 count=0
 for p in wanted:
  pattern=re.compile(r'(?:^|\.)sdt_sdt___'+re.escape(p['name'].replace('-','__'))+r'(?:\.[0-9]+)?$')
  defs=[s for s in obj.symbols if pattern.search(s['name'])];assert defs,(mod,p['name'])
  for symbol in defs:
   matches=[(patch,target) for probe,patch,target in sites if probe==(symbol['section'],symbol['value'])];assert matches,(mod,p['name'])
   for patch,target in matches:
    for sec,offset in (patch,target):assert obj.sections[sec][2]&4 and 0<=offset<obj.sections[sec][5]
    sec,offset=patch;assert obj.section_data(sec)[offset:offset+5]==bytes.fromhex('660f1f0400')
    count+=1
 results.append(dict(module=mod,path=str(path),contracts=len(wanted),executable_sites=count,status=0))
 print(mod,len(wanted),'contracts',count,'sites',flush=True)
(O/'linked-site-results.json').write_text(json.dumps(results,indent=2)+'\n')
