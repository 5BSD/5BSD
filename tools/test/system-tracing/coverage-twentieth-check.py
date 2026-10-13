#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import json,importlib.util,subprocess,os
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-twentieth-validation');T=S/'tools/test/system-tracing'
sp=importlib.util.spec_from_file_location('dof',T/'coverage-fourth-dof.py');d=importlib.util.module_from_spec(sp);sp.loader.exec_module(d)
inv=json.loads((T/'coverage-twentieth.json').read_text())['probes']; results=[]
for comp in dict.fromkeys(x['component'] for x in inv):
 name=Path(comp).name; binary=name+'.so.1' if comp.startswith('lib/') else name
 on=O/'base'/(comp.replace('/','_')+'-yes')/binary;off=O/'base'/(comp.replace('/','_')+'-no')/binary
 probes=d.dof_probes(d.elf_sections(on).get('.SUNW_dof',b''));disabled=d.dof_probes(d.elf_sections(off).get('.SUNW_dof',b''))
 for p in [p for p in inv if p['component']==comp]:
  matches=[x for x in probes if x['provider']==p['provider'] and x['name']==p['name']]
  assert matches and all(x['offsets']>0 and x['argc']==len(p['types']) for x in matches),(p,matches)
  assert not any(x['provider']==p['provider'] for x in disabled),(off,p)
 results.append(dict(component=comp,probes=probes,disabled_absent=True))
 print(comp,'linked DOF and tracing-disabled absence PASS')
(O/'dof-results.json').write_text(json.dumps(results,indent=2)+'\n')
