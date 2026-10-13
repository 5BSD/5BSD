#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile conditional configurations and verify expected SDT presence/absence."""
from pathlib import Path
import concurrent.futures,importlib.util,json,os,re,subprocess
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-sixteenth-validation');T=O/'variants';T.mkdir(exist_ok=True)
rows=json.loads((O/'kernel/results.json').read_text())
spec=importlib.util.spec_from_file_location('elf',S/'tools/test/system-tracing/coverage-sixth-objects.py');elf=importlib.util.module_from_spec(spec);spec.loader.exec_module(elf)
jobs=[('no-numa','sys/vm/vm_domainset.c','#undef NUMA\n',['memory__domains__wait'],[]),('no-reservations','sys/vm/vm_reserv.c','#define VM_NRESERVLEVEL 0\n',['memory__reservation__reclaim'],[]),('rtwn-no-watchdog','sys/dev/rtwn/if_rtwn.c','#define D4054 1\n',['rtwn__watchdog__expired'],['rtwn__init__start','rtwn__init__done']),('rtwn-no-firmware','sys/dev/rtwn/if_rtwn.c','#define RTWN_WITHOUT_UCODE 1\n',[],['rtwn__init__start','rtwn__init__done','rtwn__watchdog__expired'])]
def run(job):
 name,source,header,absent,present,hooks=job;row=next(r for r in rows if r['source']==source and r['name'].endswith('-'+str(hooks)))
 tag=name+'-'+str(hooks);inc=T/(tag+'.h');inc.write_text(header);cmd=row['command'].copy();at=cmd.index('-c');cmd[at:at]=['-include',str(inc)];cmd[-1]=str(T/(tag+'.o'))
 r=subprocess.run(cmd,cwd=row['cwd'],capture_output=True,text=True);(T/(tag+'.log')).write_text(r.stdout+r.stderr)
 if r.returncode:
  assert tag.startswith('rtwn-no-watchdog'),(tag,r.stderr)
  baseline=cmd.copy();baseline[baseline.index('-c')+1]=str(O/'before'/source);baseline[-1]=str(T/(tag+'-before.o'));at=baseline.index('-c');baseline[at:at]=['-I'+str((S/source).parent)]
  old=subprocess.run(baseline,cwd=row['cwd'],capture_output=True,text=True);(T/(tag+'-before.log')).write_text(old.stdout+old.stderr)
  diagnostics=lambda text:re.findall(r'error: (.*)',text)
  assert old.returncode!=0 and diagnostics(old.stderr)==diagnostics(r.stderr),(tag,old.stderr,r.stderr)
  assert len(diagnostics(r.stderr))==2 and all(n in r.stderr for n in ['IEEE80211_FEXT_WATCHDOG','ieee80211_tx_watchdog_stop'])
  pp=cmd.copy();pp[pp.index('-c')]='-E';pp[-1]=str(T/(tag+'.i'));subprocess.run(pp,cwd=row['cwd'],check=True,capture_output=True)
  preprocessed=Path(pp[-1]).read_text();assert 'rtwn__watchdog__expired' not in preprocessed
  return dict(variant=tag,source=source,status=0,compile_status=r.returncode,baseline_compile_status=old.returncode,result='unsupported existing D4054 APIs; baseline diagnostics match; guarded event absent',diagnostics=diagnostics(r.stderr))
 obj=elf.Object(Path(cmd[-1]));names=[s['name'] for s in obj.symbols]
 for name in absent+([] if hooks else present):assert not any('sdt_sdt___'+name in n for n in names),(tag,name)
 if hooks:
  for name in present:assert any('sdt_sdt___'+name in n for n in names),(tag,name)
 print(tag,'PASS',flush=True);return dict(variant=tag,source=source,command=cmd,status=0)
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:results=list(pool.map(run,[(*j,h) for j in jobs for h in [True,False]]))
(O/'variant-results.json').write_text(json.dumps(results,indent=2)+'\n')
