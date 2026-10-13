#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile changed kernel sources with native per-source flags and hooks on/off."""
from pathlib import Path
import concurrent.futures,json,os,re,shlex,subprocess,sys
S=Path('/usr/src');K=Path('/usr/obj/usr/src/amd64.amd64/sys/GENERIC-NODEBUG');O=Path('/usr/obj/5bsd-dtrace-eighteenth-validation');T=O/'kernel';T.mkdir(exist_ok=True)
(T/'nohooks.h').write_text('#undef KDTRACE_HOOKS\n')
modules=json.loads((S/'tools/test/system-tracing/coverage-eighteenth-build.json').read_text())
source_module={f:m for m,fs in modules.items() for f in fs}
files=sorted({p['source'] for p in json.loads((S/'tools/test/system-tracing/coverage-eighteenth.json').read_text())['probes']})
if len(sys.argv)>1:
 assert set(sys.argv[1:])<=set(files)
 files=sys.argv[1:]
opts=' '.join(sorted(set(re.findall(r'^#define\s+(\w+)', '\n'.join(p.read_text() for p in K.glob('opt*.h')),re.M))))
commands={m:['make','-C',str(S/'sys/modules'/m),'-m',str(S/'share/mk'),'MAKEOBJDIR='+str(K/'modules/usr/src/sys/modules'/m),'KERNBUILDDIR='+str(K),'KERN_OPTS='+opts] for m in modules}
flags=shlex.split(subprocess.check_output(['make','-C',str(K),'-V','${CFLAGS}'],text=True))
moduleflags={m:shlex.split(subprocess.check_output(c+['-V','${CFLAGS}'],text=True)) for m,c in commands.items()}
def run(job):
 f,h=job;module=source_module.get(f);cwd=K;ff=flags
 if module:
  cwd=K/'modules/usr/src/sys/modules'/module
  ff=moduleflags[module]+shlex.split(subprocess.check_output(commands[module]+['-V','${CFLAGS.'+Path(f).name+'}'],text=True))
 tag=Path(f).stem+'-'+str(h);cmd=['cc',*ff,'-Werror']
 if not h:cmd+=['-include',str(T/'nohooks.h')]
 cmd+=['-c',str(S/f),'-o',str(T/(tag+'.o'))]
 r=subprocess.run(cmd,cwd=cwd,capture_output=True,text=True);(T/(tag+'.log')).write_text(shlex.join(cmd)+'\n'+r.stdout+r.stderr)
 print(tag,r.returncode,flush=True)
 if r.returncode:print(r.stderr[-2400:],flush=True)
 return dict(source=f,name=tag,cwd=str(cwd),command=cmd,status=r.returncode)
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:results=list(pool.map(run,[(f,h) for f in files for h in [True,False]]))
if len(sys.argv)>1 and (T/'results.json').exists():
 previous={r['name']:r for r in json.loads((T/'results.json').read_text())};previous.update({r['name']:r for r in results});results=list(previous.values())
(T/'results.json').write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(int(any(r['status'] for r in results)))
