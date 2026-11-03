#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Actual static-library lifecycle tests with link-time device/module mocks."""
from pathlib import Path
import hashlib,json,os,resource,subprocess,sys
out,world=(Path(p).resolve() for p in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out,world)) or out.exists():
    raise SystemExit('Use new /usr/obj output and the instrumented build prefix')
root=Path(__file__).resolve().parents[3]
archive=world/root.relative_to('/')/'amd64.amd64/lib/libvmmapi/libvmmapi.a'
source=root/'lib/libvmmapi/vmmapi.c'
if archive.stat().st_mtime_ns<source.stat().st_mtime_ns: raise SystemExit('Rebuild libvmmapi first')
out.mkdir(parents=True)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
fixture=Path(__file__).with_suffix('.c');binary=out/'lifecycle-test'
command=['/usr/bin/cc','-g','-fprofile-instr-generate','-I'+str(root/'lib/libvmmapi'),'-I'+str(root/'sys'),'-I'+str(world/'source-includes'),str(fixture),str(archive),'-lutil','-Wl,--wrap=open,--wrap=close,--wrap=ioctl,--wrap=modfind,--wrap=kldload,--wrap=malloc,--wrap=fcntl,--wrap=cap_rights_limit,--wrap=cap_ioctls_limit','-o',str(binary)]
subprocess.run(command,check=True)
env=os.environ.copy();env['LLVM_PROFILE_FILE']=str(out/'%p-%m.profraw')
env['VMMAPI_TEST_PROFILE_DIR']=str(out)
p=subprocess.run([str(binary)],env=env,capture_output=True,text=True,timeout=30)
result={'status':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'passed':p.returncode==0 and 'PASS: actual-library lifecycle and identity' in p.stdout and 'LLVM Profile Error' not in p.stderr}
(out/'results.json').write_text(json.dumps(result,indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'command':command,'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (source,archive,fixture,Path(__file__),binary)},'scope':'Actual static library, module/device operations mocked; real opens limited to validation artifacts'},indent=2)+'\n')
print(json.dumps(result));raise SystemExit(not result['passed'])
