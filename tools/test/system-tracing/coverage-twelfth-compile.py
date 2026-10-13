#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile exact module sources with native options and hooks on/off."""
from pathlib import Path
import concurrent.futures,json,os,shlex,subprocess
S=Path('/usr/src');K=Path('/usr/obj/usr/src/amd64.amd64/sys/GENERIC-NODEBUG');O=Path('/usr/obj/5bsd-dtrace-twelfth-validation');T=O/'kernel';T.mkdir(exist_ok=True)
(T/'nohooks.h').write_text('#undef KDTRACE_HOOKS\n')
inv=json.loads((S/'tools/test/system-tracing/coverage-twelfth.json').read_text())
commands=json.loads((O/'modules/results.json').read_text())
flags={r['module']:shlex.split(subprocess.check_output(r['command'][:-1]+['-V','${CFLAGS}'],text=True)) for r in commands}
def run(job):
 f,h=job;module='pf' if '/netpfil/' in f else 'zfs';cwd=K/'modules/usr/src/sys/modules'/module
 tag=Path(f).stem+'-'+str(h)
 module_command=next(r['command'] for r in commands if r['module']==module)
 per_source=shlex.split(subprocess.check_output(module_command[:-1]+['-V','${CFLAGS.'+Path(f).name+'}'],text=True))
 cmd=['cc',*flags[module],*per_source,'-Werror']
 if not h:cmd+=['-include',str(T/'nohooks.h')]
 cmd+=['-c',str(S/f),'-o',str(T/(tag+'.o'))]
 r=subprocess.run(cmd,cwd=cwd,capture_output=True,text=True);(T/(tag+'.log')).write_text(shlex.join(cmd)+'\n'+r.stdout+r.stderr)
 print(tag,r.returncode,flush=True)
 if r.returncode:print(r.stderr[-3000:],flush=True)
 return dict(name=tag,command=cmd,status=r.returncode)
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
 results=list(pool.map(run,[(f,h) for f in sorted({p['source'] for p in inv['probes']}) for h in [True,False]]))
(T/'results.json').write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(int(any(r['status'] for r in results)))
