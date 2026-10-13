#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import json,subprocess,shlex,concurrent.futures,os
S=Path('/usr/src');K=Path('/usr/obj/usr/src/amd64.amd64/sys/GENERIC-NODEBUG');O=Path('/usr/obj/5bsd-dtrace-eleventh-validation/kernel')
flags=shlex.split(subprocess.check_output(['make','-C',str(K),'-V','${CFLAGS}'],text=True))
results=[]
for hooks in [True,False]:
 tag='uipc_sem-minimal-'+str(hooks);h=O/(tag+'.h');h.write_text('#undef MAC\n#undef COMPAT_FREEBSD32\n'+('' if hooks else '#undef KDTRACE_HOOKS\n'))
 cmd=['cc',*flags,'-Werror','-include',str(h),'-c',str(S/'sys/kern/uipc_sem.c'),'-o',str(O/(tag+'.o'))]
 r=subprocess.run(cmd,cwd=K,capture_output=True,text=True);(O/(tag+'.log')).write_text(shlex.join(cmd)+'\n'+r.stdout+r.stderr);results.append(dict(name=tag,status=r.returncode,command=cmd));print(tag,r.returncode)
(O/'variant-results.json').write_text(json.dumps(results,indent=2)+'\n')
assert all(r['status']==0 for r in results)
