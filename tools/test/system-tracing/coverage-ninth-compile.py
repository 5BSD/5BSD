#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
# Prepared native amd64 validation only; see COVERAGE-NINTH.
import os,subprocess,shlex,json,concurrent.futures
from pathlib import Path
S=Path('/usr/src'); K=Path('/usr/obj/usr/src/amd64.amd64/sys/GENERIC-NODEBUG'); O=Path('/usr/obj/5bsd-dtrace-ninth-validation/kernel'); O.mkdir(parents=True,exist_ok=True)
(O/'nohooks.h').write_text('#undef KDTRACE_HOOKS\n')
flags=shlex.split(subprocess.check_output(['make','-C',str(K),'-V','${CFLAGS}'],text=True))
files=['sys/dev/md/md.c', 'sys/fs/cd9660/cd9660_vnops.c', 'sys/fs/nullfs/null_subr.c', 'sys/fs/tarfs/tarfs_io.c', 'sys/fs/udf/udf_vnops.c', 'sys/fs/unionfs/union_subr.c', 'sys/kern/tty.c', 'sys/net/if_bridge.c', 'sys/net/if_clone.c', 'sys/net/if_lagg.c', 'sys/net/if_tuntap.c', 'sys/net/if_vlan.c']
def run(job):
 f,h=job; ident=Path(f).stem+'-'+str(h); cmd=['cc',*flags,'-Werror']
 if Path(f).stem=='tarfs_io': cmd+=['-I/usr/src/sys/contrib/zstd/lib/freebsd']
 if not h: cmd+=['-include',str(O/'nohooks.h')]
 cmd+=['-c',str(S/f),'-o',str(O/(ident+'.o'))]
 r=subprocess.run(cmd,cwd=K,capture_output=True,text=True); (O/(ident+'.log')).write_text(shlex.join(cmd)+'\n'+r.stdout+r.stderr)
 print(ident,r.returncode,flush=True)
 if r.returncode: print(r.stderr[-3500:],flush=True)
 return dict(name=ident,command=cmd,status=r.returncode)
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as p: results=list(p.map(run,[(f,h) for f in files for h in [True,False]]))
(O/'results.json').write_text(json.dumps(results,indent=2))

raise SystemExit(int(any(r["status"] != 0 for r in results)))
