#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Native prepared-tree kernel compilation with tracing enabled and disabled."""
from pathlib import Path
import concurrent.futures,json,os,re,shlex,subprocess
S=Path('/usr/src');K=Path('/usr/obj/usr/src/amd64.amd64/sys/GENERIC-NODEBUG');O=Path('/usr/obj/5bsd-dtrace-fifteenth-validation');T=O/'kernel';T.mkdir(exist_ok=True)
(T/'nohooks.h').write_text('#undef KDTRACE_HOOKS\n')
inv=json.loads((S/'tools/test/system-tracing/coverage-fifteenth.json').read_text())
files=sorted({p['source'] for p in inv['probes'] if p['kind']=='kernel'})
opts=' '.join(sorted(set(re.findall(r'^#define\s+(\w+)', '\n'.join(p.read_text() for p in K.glob('opt*.h')),re.M))))
commands=[dict(module=m,command=['make','-C',str(S/'sys/modules'/m),'-m',str(S/'share/mk'),'MAKEOBJDIR='+str(K/'modules/usr/src/sys/modules'/m),'KERNBUILDDIR='+str(K),'KERN_OPTS='+opts,'all']) for m in ['pf','zfs']]
flags=shlex.split(subprocess.check_output(['make','-C',str(K),'-V','${CFLAGS}'],text=True))
moduleflags={r['module']:shlex.split(subprocess.check_output(r['command'][:-1]+['-V','${CFLAGS}'],text=True)) for r in commands}
def run(job):
 f,h=job;cwd=K;opts=flags
 module='zfs' if '/openzfs/' in f else 'pf' if '/netpfil/' in f else None
 if module:
  row=next(r for r in commands if r['module']==module);cwd=K/'modules/usr/src/sys/modules'/module
  opts=moduleflags[module]+shlex.split(subprocess.check_output(row['command'][:-1]+['-V','${CFLAGS.'+Path(f).name+'}'],text=True))
 tag=Path(f).stem+'-'+str(h);cmd=['cc',*opts,'-Werror']
 if not h:cmd+=['-include',str(T/'nohooks.h')]
 cmd+=['-c',str(S/f),'-o',str(T/(tag+'.o'))]
 r=subprocess.run(cmd,cwd=cwd,capture_output=True,text=True);(T/(tag+'.log')).write_text(shlex.join(cmd)+'\n'+r.stdout+r.stderr)
 print(tag,r.returncode,flush=True)
 if r.returncode:print(r.stderr[-2500:],flush=True)
 return dict(source=f,name=tag,command=cmd,status=r.returncode)
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as p:results=list(p.map(run,[(f,h) for f in files for h in [True,False]]))
(T/'results.json').write_text(json.dumps(results,indent=2))
raise SystemExit(int(any(r['status'] for r in results)))
