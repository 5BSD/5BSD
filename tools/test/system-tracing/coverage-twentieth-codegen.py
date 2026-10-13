#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess,json,shlex,importlib.util,re
S=Path('/usr/src'); O=Path('/usr/obj/5bsd-dtrace-twentieth-validation'); out=O/'codegen';out.mkdir(exist_ok=True)
sp=importlib.util.spec_from_file_location('dof',S/'tools/test/system-tracing/coverage-fourth-dof.py'); d=importlib.util.module_from_spec(sp);sp.loader.exec_module(d)
results=[]
for rel in json.loads((O/'changed.json').read_text()):
 if not rel.endswith('.c'):continue
 comp='bin/zsh' if rel.startswith('contrib/zsh') else str(Path(rel).parent)
 if comp=='usr.sbin/capsule':continue # Existing no-DTrace header was broken; fixed intentionally.
 objdir=O/'base'/(comp.replace('/','_')+'-no'); lines=(objdir/'build.log').read_text().splitlines()
 # Incremental make logs may have no compile line. Ask make for the expanded toolchain.
 obj=Path(rel).stem+('.o' if comp.startswith('lib/') else '.pieo')
 cmd=['make','-C',str(S/comp),'-m',str(S/'share/mk'),'MAKEOBJDIR='+str(objdir),'SRCTOP='+str(S),'MK_TESTS=no','MK_DTRACE=no','SYSROOT=/usr/obj/usr/src/amd64.amd64/tmp','CFLAGS_LAST=--sysroot=/usr/obj/usr/src/amd64.amd64/tmp','-V','CC','-V','CFLAGS']
 vals=subprocess.check_output(cmd,text=True).splitlines();cc=shlex.split(vals[0]); flags=shlex.split(vals[1]);extra=['-fpie','-DPIC'] if obj.endswith('.pieo') else []
 current=objdir/obj; assert current.exists(),current
 base=O/'before'/rel;target=out/(rel.replace('/','_')+'.o')
 run=cc+extra+flags+['-I'+str(S/Path(rel).parent),'-fmacro-prefix-map='+str(O/'before')+'='+str(S),'-c',str(base),'-o',str(target)]
 r=subprocess.run(run,cwd=objdir,capture_output=True,text=True);target.with_suffix('.log').write_text(r.stdout+r.stderr)
 equal=r.returncode==0 and d.elf_sections(target).get('.text')==d.elf_sections(current).get('.text')
 results.append(dict(source=rel,status=r.returncode,unchanged_text=equal,command=run));print(rel,r.returncode,equal,flush=True)
(O/'codegen-results.json').write_text(json.dumps(results,indent=2)+'\n')
