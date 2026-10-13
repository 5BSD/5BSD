#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
# Prepared native amd64 validation only; see COVERAGE-SEVENTH.
from pathlib import Path
import os,subprocess,json
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-seventh-validation/tests');O.mkdir(parents=True,exist_ok=True)
groups=[('tests/usr.sbin/bluetooth/BSDBluetooth',['mesh_df_test','mesh_manager_test','audio_avdtp_test','discovery_test','mesh_remote_prov_test','mesh_lpn_test','iso_lifecycle_test','meshd_persist_test','meshd_persist_fault_test','meshd_security_test','mesh_key_refresh_test','mesh_proxy_test','mesh_friend_test','mesh_cfg_model_test','conn_test','probe_tap_test']),('tests/sys/kern/vsock_device_harness',['migration_session_test','virtio_admin_test','virtio_admin_device_parts_test','snapshot_portable_test'])]
results=[]
for group,names in groups:
 out=O/group.replace('/','_');out.mkdir(exist_ok=True)
 cmd=['make','-C',str(S/group),'-m',str(S/'share/mk'),'-j'+str(os.cpu_count()),'SRCTOP='+str(S),'MAKEOBJDIR='+str(out),'MK_DTRACE=no','SYSROOT=/usr/obj/usr/src/amd64.amd64/tmp','CFLAGS_LAST=--sysroot=/usr/obj/usr/src/amd64.amd64/tmp','LDFLAGS_LAST=--sysroot=/usr/obj/usr/src/amd64.amd64/tmp',*names]
 with (out/'build.log').open('w') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
 print(group,'build',r.returncode,flush=True)
 results.append(dict(group=group,stage='build',status=r.returncode,command=cmd))
 if r.returncode:
  print('\n'.join((out/'build.log').read_text().splitlines()[-18:]),flush=True);continue
 for name in names:
  r=subprocess.run([str(out/name),'-l'],capture_output=True,text=True)
  if r.returncode: results.append(dict(name=name,stage='list',status=r.returncode));continue
  for line in r.stdout.splitlines():
   if not line.startswith('ident: '):continue
   case=line[7:]; wd=out/(name+'-'+case);wd.mkdir(exist_ok=True)
   cmd=[str(out/name),'-s',str(out),'-r',str(wd/'result'),case]
   with (wd/'output').open('w') as f:r=subprocess.run(cmd,cwd=wd,stdout=f,stderr=subprocess.STDOUT,timeout=90)
   result=(wd/'result').read_text() if (wd/'result').exists() else 'no result'
   results.append(dict(name=name,case=case,status=r.returncode,result=result))
   print(name,case,result.strip(),flush=True)
(O/'results.json').write_text(json.dumps(results,indent=2)+'\n')

raise SystemExit(int(any(r["status"] != 0 or ("case" in r and r["result"].strip() != "passed") for r in results)))
