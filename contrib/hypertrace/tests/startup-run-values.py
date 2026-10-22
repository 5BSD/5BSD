#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Original portable vCPU-run validator; no kernel or vCPU execution."""
from pathlib import Path
import ctypes as C
import errno,hashlib,json,os,random,subprocess,sys
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj') or out.exists(): raise SystemExit('Use a new /usr/obj output')
out.mkdir(parents=True)
root=Path(__file__).resolve().parents[3]
source=root/'sys/dev/vmm/vmm_startup_run_request.c'
binary=out/'validator.so'
command=['/usr/bin/cc','-O0','-g','-shared','-fPIC','-fprofile-instr-generate','-fcoverage-mapping','-fprofile-update=atomic','-I'+str(root/'sys'),str(source),'-o',str(binary)]
subprocess.run(command,check=True)
lib=C.CDLL(str(binary))
class Request(C.Structure):
    _fields_=[('vcpuid',C.c_int32),('version',C.c_uint16),('size',C.c_uint16),('flags',C.c_uint32),('reserved32',C.c_uint32)]+[(n,C.c_uint64) for n in ('generation','cpuset_address','cpuset_size','exit_address','exit_size')]+[('reserved8',C.c_uint8*8)]
assert C.sizeof(Request)==64
fn=lib.vmm_startup_run_request_validate
fn.argtypes=[C.POINTER(Request),C.c_uint32,C.c_uint64,C.c_uint64,C.c_uint64];fn.restype=C.c_int
maximum=2**64-1
results=[]
def valid():return Request(vcpuid=3,version=1,size=64,generation=42,cpuset_address=4096,cpuset_size=8,exit_address=8192,exit_size=256)
def check(name,r,expected,maxv=8,maxset=128,exitsize=256,maxaddr=maximum):
    before=None if r is None else bytes(r)
    status=fn(None if r is None else C.byref(r),maxv,maxset,exitsize,maxaddr)
    results.append({'case':name,'expected':expected,'status':status,'passed':status==expected and (r is None or bytes(r)==before)})
check('valid',valid(),0);check('null',None,errno.EINVAL)
for key in ('maxv','maxset','exitsize'):check('zero-'+key,valid(),errno.EINVAL,**{key:0})
for field,value in [('version',0),('version',2),('size',63),('size',65),('flags',1),('vcpuid',-1),('vcpuid',8),('reserved32',1),('generation',0),('cpuset_size',0),('cpuset_size',129),('exit_size',0),('exit_size',255),('exit_size',257),('cpuset_address',0),('exit_address',0)]:
    r=valid();setattr(r,field,value);check(field+'-'+str(value),r,errno.EINVAL)
for i in range(8):
    r=valid();r.reserved8[i]=255;check('reserved-'+str(i),r,errno.EINVAL)
for field,value in [('vcpuid',0),('vcpuid',7),('generation',maximum),('cpuset_size',1),('cpuset_size',128)]:
    r=valid();setattr(r,field,value);check('boundary-'+field+'-'+str(value),r,0)
# Independent closed-interval arithmetic (unbounded Python integers), including
# adjacency, containment, equal starts and both orderings near address limits.
for limit in (2**32-1,maximum):
    pairs=[(4096,4104),(4096,4103),(8192,7936),(8192,7937),(4096,4096),
           (limit-7,4096),(limit-6,4096),(4096,limit-255),(4096,limit-254),
           (limit,4096),(4096,limit),(limit+1 if limit<maximum else maximum,4096)]
    for i,(left,right) in enumerate(pairs):
        r=valid();r.cpuset_address=left;r.exit_address=right
        a=(left,left+7);b=(right,right+255)
        ok=0<a[0]<=a[1]<=limit and 0<b[0]<=b[1]<=limit and (a[1]<b[0] or b[1]<a[0])
        check('range-%d-%d'%(limit,i),r,0 if ok else errno.EINVAL,maxaddr=limit)
rng=random.Random(0x5b5d)
for i in range(512):
    r=valid();limit=rng.choice([2**16-1,2**32-1,maximum])
    r.cpuset_size=rng.randrange(1,129)
    r.cpuset_address=rng.randrange(max(1,limit-512),limit+1) if i%2 else rng.randrange(1,65536)
    r.exit_address=rng.randrange(max(1,limit-512),limit+1) if i%3 else rng.randrange(1,65536)
    left=(r.cpuset_address,r.cpuset_address+r.cpuset_size-1);right=(r.exit_address,r.exit_address+255)
    ok=left[1]<=limit and right[1]<=limit and (left[1]<right[0] or right[1]<left[0])
    check('generated-'+str(i),r,0 if ok else errno.EINVAL,maxaddr=limit)
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'command':command,'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (source,binary,Path(__file__))},'seed':0x5b5d,'pid':os.getpid(),'scope':'Original source compiled in portable userspace mode; not a kernel build or dispatch test'},indent=2)+'\n')
for r in results:
    if not r['passed']:print(r)
print(f"{sum(r['passed'] for r in results)}/{len(results)} startup validator checks passed")
raise SystemExit(not all(r['passed'] for r in results))
