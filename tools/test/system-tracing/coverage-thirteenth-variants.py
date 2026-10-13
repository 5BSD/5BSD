#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Prepared native amd64 alternate-option builds, without changing kernel config."""
from pathlib import Path
import concurrent.futures,json,os,shlex,subprocess
S=Path('/usr/src'); K=Path('/usr/obj/usr/src/amd64.amd64/sys/GENERIC-NODEBUG'); O=Path('/usr/obj/5bsd-dtrace-thirteenth-validation/kernel')
flags=shlex.split(subprocess.check_output(['make','-C',str(K),'-V','${CFLAGS}'],text=True))
files=['sys/kern/vfs_extattr.c','sys/kern/vfs_acl.c','sys/kern/sys_procdesc.c','sys/kern/kern_resource.c','sys/vm/vm_mmap.c','sys/net/if_epair.c']
def run(job):
 source,hooks=job;tag=Path(source).stem+'-minimal-'+str(hooks);header=O/(tag+'.h')
 header.write_text('#undef MAC\n#undef RACCT\n#undef COMPAT_FREEBSD32\n#undef RSS\n'+('' if hooks else '#undef KDTRACE_HOOKS\n'))
 cmd=['cc',*flags,'-Werror','-include',str(header),'-c',str(S/source),'-o',str(O/(tag+'.o'))]
 # Existing kern_mprotect error local is unused when MAC is off.
 # Reproduced with the saved baseline; retain the diagnostic as a warning.
 if source=='sys/vm/vm_mmap.c': cmd.insert(1,'-Wno-error=unused-variable')
 r=subprocess.run(cmd,cwd=K,capture_output=True,text=True)
 (O/(tag+'.log')).write_text(shlex.join(cmd)+'\n'+r.stdout+r.stderr)
 print(tag,r.returncode,flush=True)
 return dict(name=tag,status=r.returncode,command=cmd)
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
 results=list(pool.map(run,[(f,h) for f in files for h in (True,False)]))
(O/'variant-results.json').write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(int(any(r['status'] for r in results)))
