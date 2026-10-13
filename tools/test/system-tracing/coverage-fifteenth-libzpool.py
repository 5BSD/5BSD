#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile the changed portable OpenZFS sources in base libzpool, no install."""
import json,os,subprocess,shlex
from pathlib import Path
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-fifteenth-validation');T=O/'base/libzpool';T.mkdir(parents=True,exist_ok=True)
R='/usr/obj/usr/src/amd64.amd64/tmp'
cmd=['make','-C',str(S/'cddl/lib/libzpool'),'-m',str(S/'share/mk'),'-j'+str(os.cpu_count()),'SRCTOP='+str(S),'MAKEOBJDIR='+str(T),'SYSROOT='+R,'CFLAGS_LAST=--sysroot='+R,'LDFLAGS_LAST=--sysroot='+R,'MK_TESTS=no','dsl_scan.o','vdev_rebuild.o']
with (T/'build.log').open('w') as log:
 log.write(shlex.join(cmd)+'\n');log.flush();r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
(O/'libzpool-results.json').write_text(json.dumps([dict(command=cmd,status=r.returncode,objects=['dsl_scan.o','vdev_rebuild.o'])],indent=2)+'\n')
raise SystemExit(r.returncode)
