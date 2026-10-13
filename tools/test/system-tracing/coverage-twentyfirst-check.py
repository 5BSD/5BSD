#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import json,subprocess,importlib.util,re,os
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-twentyfirst-validation');T=S/'tools/test/system-tracing';R=O/'tests';R.mkdir(exist_ok=True)
spec=importlib.util.spec_from_file_location('dof',T/'coverage-fourth-dof.py');d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
inv=json.loads((T/'coverage-twentyfirst.json').read_text())['probes'];dofs=[];results=[]
for comp in dict.fromkeys(p['component'] for p in inv if p['kind']=='user'):
 name=Path(comp).name;binary=name+'.so.1' if comp.startswith('lib/') else name
 on=O/'base'/(comp.replace('/','_')+'-yes')/binary;off=O/'base'/(comp.replace('/','_')+'-no')/binary
 actual=d.dof_probes(d.elf_sections(on).get('.SUNW_dof',b''));disabled=d.dof_probes(d.elf_sections(off).get('.SUNW_dof',b''))
 for p in [p for p in inv if p.get('component')==comp]:
  found=[q for q in actual if q['provider']==p['provider'] and q['name']==p['name']]
  assert found and all(q['offsets'] and q['argc']==len(p['types']) for q in found),(comp,p)
  assert not any(q['provider']==p['provider'] for q in disabled)
 dofs.append(dict(component=comp,probes=actual,disabled_absent=True));print(comp,'DOF PASS',flush=True)
(O/'dof-results.json').write_text(json.dumps(dofs,indent=2))
def run(cmd,name,cwd=R):
 r=subprocess.run(cmd,cwd=cwd,capture_output=True,text=True);(R/(name+'.log')).write_text(r.stdout+r.stderr);results.append(dict(test=name,status=r.returncode));print(name,r.returncode,flush=True)
 if r.returncode:print((r.stdout+r.stderr)[-1400:])
 return r
for mode in ('yes','no'):
 comp='libcapsulert';lib=O/'base'/('lib_'+comp+'-'+mode);source=S/'lib'/comp/'tests/claim_parse_test.c';exe=R/('claims-'+mode)
 cmd=['cc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-I'+str(S/'sys'),'-I'+str(S/'lib/libcapsulert'),'-I'+str(S/'contrib/libucl/include'),str(source),'-L'+str(lib),'-Wl,-rpath,'+str(lib),'-lcapsulert','-lprivateucl','-lprivateatf-c','-o',str(exe)]
 if run(cmd,'claims-build-'+mode).returncode==0:
  for case in re.findall(r'ATF_TC_WITHOUT_HEAD\((\w+)\)',source.read_text()):run([str(exe),'-r',str(R/(case+'-'+mode+'.result')),case],case+'-'+mode)
# These existing tests inject allocation failures and use pipes, not /dev/oes.
for name in ('ownership_test','path_test'):
 source=S/'lib/liboes/tests'/(name+'.c');exe=R/name
 if run(['cc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-I'+str(S/'sys'),'-I'+str(S/'lib/liboes'),'-I'+str(S/'lib/libservice'),str(source),'-lprivateatf-c','-o',str(exe)],name+'-build').returncode==0:
  for case in re.findall(r'ATF_TC_WITHOUT_HEAD\((\w+)\)',source.read_text()):run([str(exe),'-r',str(R/(case+'.result')),case],case)
(O/'test-results.json').write_text(json.dumps(results,indent=2)+'\n');assert all(r['status']==0 for r in results)
