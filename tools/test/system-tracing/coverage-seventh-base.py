#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
# Prepared native amd64 validation only; see COVERAGE-SEVENTH.
import os,subprocess,json
from pathlib import Path
S=Path('/usr/src'); O=Path('/usr/obj/5bsd-dtrace-seventh-validation'); results=[]
for comp in ['lib/libmesh','lib/virtual_oss/bt','usr.sbin/bhyve','usr.sbin/bluetooth/BSDBluetooth','usr.sbin/bluetooth/meshd']:
 for hooks in ['yes','no']:
  modes=['yes','no'] if comp.endswith('/bhyve') else [None]
  for mode in modes:
   ident=comp.replace('/','_')+'-'+hooks+('-snapshot-'+mode if mode else '')
   out=O/'base'/ident; out.mkdir(parents=True,exist_ok=True)
   cmd=['make','-C',str(S/comp),'-m',str(S/'share/mk'),'-j'+str(os.cpu_count()),'SRCTOP='+str(S),'MAKEOBJDIR='+str(out),'MK_TESTS=no','MK_DTRACE='+hooks]
   if mode: cmd+=['MK_BHYVE_SNAPSHOT='+mode, 'SYSROOT=/usr/obj/usr/src/amd64.amd64/tmp', 'CFLAGS_LAST=--sysroot=/usr/obj/usr/src/amd64.amd64/tmp', 'LDFLAGS_LAST=--sysroot=/usr/obj/usr/src/amd64.amd64/tmp']
   if comp.endswith('/meshd'): cmd+=['LIBBLEMESHDIR='+str(O/'base'/('lib_libmesh-'+hooks))]
   cmd+=['all']
   with (out/'build.log').open('w') as f: r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
   results.append(dict(name=ident,status=r.returncode,command=cmd))
   (O/'base-results.json').write_text(json.dumps(results,indent=2)+'\n')
   print(ident,r.returncode,flush=True)
   if r.returncode: print('\n'.join((out/'build.log').read_text().splitlines()[-12:]),flush=True)

raise SystemExit(int(any(r["status"] != 0 for r in results)))
