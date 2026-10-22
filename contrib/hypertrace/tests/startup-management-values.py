#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Portable startup-management validation/encoding with original sources."""
from pathlib import Path
import ctypes as C
import errno,hashlib,itertools,json,subprocess,sys
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj') or out.exists():raise SystemExit('Use new /usr/obj output')
out.mkdir(parents=True);root=Path(__file__).resolve().parents[3]
sources=[root/'sys/dev/vmm'/n for n in ('vmm_startup_request.c','vmm_startup_mode.c')]
binary=out/'validator.so'
command=['/usr/bin/cc','-O0','-g','-shared','-fPIC','-fprofile-instr-generate','-fcoverage-mapping','-fprofile-update=atomic','-I'+str(root/'sys'),*map(str,sources),'-o',str(binary)]
subprocess.run(command,check=True);lib=C.CDLL(str(binary))
class Mode(C.Structure):
    _fields_=[(k,C.c_uint8) for k in ('owner','execution','locked','reserved8')]+[('reserved32',C.c_uint32)]
class Status(C.Structure):
    _fields_=[('mode',Mode),('generation',C.c_uint64),('expected_vcpus',C.c_uint32),('entered_vcpus',C.c_uint32),('bootstrap_entered',C.c_uint8),('phase',C.c_uint8),('reserved16',C.c_uint16),('reserved32',C.c_uint32)]
class Request(C.Structure):
    _fields_=[(k,C.c_uint16) for k in ('version','size','operation','flags')]+[('generation',C.c_uint64),('expected_vcpus',C.c_uint32),('entered_vcpus',C.c_uint32)]+[(k,C.c_uint8) for k in ('bootstrap_entered','phase','owner','execution')]+[('reserved8',C.c_uint8*20)]
assert C.sizeof(Request)==48 and C.sizeof(Status)==32
validate=lib.vmm_startup_request_validate;validate.argtypes=[C.POINTER(Request),C.c_uint32];validate.restype=C.c_int
encode=lib.vmm_startup_request_encode_status;encode.argtypes=[C.POINTER(Request),C.c_uint32,C.POINTER(Status),C.POINTER(Request)];encode.restype=C.c_int
results=[]
def request(op=4):return Request(version=1,size=48,operation=op,generation=42 if op in (2,3) else 0,expected_vcpus=2 if op==1 else 0)
def check(name,r,expected,maximum=8):
    before=None if r is None else bytes(r);status=validate(None if r is None else C.byref(r),maximum)
    results.append({'case':name,'status':status,'passed':status==expected and (r is None or bytes(r)==before)})
for op in range(1,5):check('valid-'+str(op),request(op),0)
check('null',None,errno.EINVAL);check('zero-max',request(),errno.EINVAL,0)
for field,value in [('version',0),('size',47),('operation',0),('operation',5),('flags',1),('entered_vcpus',1),('bootstrap_entered',1),('phase',1),('owner',1),('execution',1)]:
    r=request();setattr(r,field,value);check('field-'+field,r,errno.EINVAL)
for i in range(20):
    r=request();r.reserved8[i]=1;check('reserved-'+str(i),r,errno.EINVAL)
for op in range(1,5):
    for gen,expected in itertools.product((0,42),(0,1,8,9,65535,65536)):
        r=request(op);r.generation=gen;r.expected_vcpus=expected
        ok=(gen==0 and 0<expected<=8) if op==1 else (gen!=0 and expected==0) if op in (2,3) else gen==expected==0
        check('operation-%d-%d-%d'%(op,gen,expected),r,0 if ok else errno.EINVAL)
r=request(1);r.expected_vcpus=65536;check('count-u16-overflow',r,errno.EINVAL,65536)
r.expected_vcpus=65535;check('count-u16-max',r,0,65536)
# Exhaust all small state combinations against the three allowed lifecycle
# states, rather than copying the implementation's sequence of conditions.
for phase,owner,execution,locked,expected,entered,boot in itertools.product(range(5),range(3),range(3),range(3),range(3),range(4),range(3)):
    state=Status(mode=Mode(owner,execution,locked,0,0),generation=42,expected_vcpus=expected,entered_vcpus=entered,bootstrap_entered=boot,phase=phase)
    ok=((phase,owner,execution,locked,expected,entered,boot)==(0,0,0,0,0,0,0) or
        (phase==1 and owner==execution==1 and locked==0 and expected>0 and entered<=expected and boot<=1 and boot<=entered) or
        (phase==2 and owner==execution==locked==1 and expected>0 and entered==expected and boot==1))
    r=request();output=Request();C.memset(C.byref(output),0xa5,C.sizeof(output));before=bytes(output)
    rc=encode(C.byref(r),8,C.byref(state),C.byref(output))
    wanted=request();wanted.generation=42;wanted.expected_vcpus=expected;wanted.entered_vcpus=entered;wanted.bootstrap_entered=boot;wanted.phase=phase;wanted.owner=owner;wanted.execution=execution
    passed=(rc==0 and bytes(output)==bytes(wanted)) if ok else (rc==errno.EINVAL and bytes(output)==before)
    results.append({'case':'state','values':[phase,owner,execution,locked,expected,entered,boot],'passed':passed,'status':rc})
state=Status(generation=42)
for field,value in [('generation',0),('reserved16',1),('reserved32',1)]:
    bad=Status.from_buffer_copy(state);setattr(bad,field,value);r=request();o=Request();before=bytes(o)
    rc=encode(C.byref(r),8,C.byref(bad),C.byref(o));results.append({'case':'status-'+field,'passed':rc==errno.EINVAL and bytes(o)==before})
for which in ('request','status','output'):
    r=request();o=Request();before=bytes(o)
    rc=encode(None if which=='request' else C.byref(r),8,None if which=='status' else C.byref(state),None if which=='output' else C.byref(o))
    results.append({'case':'null-'+which,'passed':rc==errno.EINVAL and bytes(o)==before})
r=request();rc=encode(C.byref(r),8,C.byref(state),C.byref(r));results.append({'case':'in-place','passed':rc==0 and r.generation==42})
for offset in (8,40):
    arena=C.create_string_buffer(96);r=Request.from_buffer(arena);C.memmove(C.byref(r),C.byref(request()),48);o=C.cast(C.byref(arena,offset),C.POINTER(Request));before=bytes(arena)
    rc=encode(C.byref(r),8,C.byref(state),o);results.append({'case':'partial-alias-'+str(offset),'passed':rc==errno.EINVAL and bytes(arena)==before})
for name in ('mode-reserved8','mode-reserved32','over-limit','invalid-request','status-output-alias'):
    r=request();state=Status(generation=42);o=Request();before=bytes(o)
    if name=='mode-reserved8':state.mode.reserved8=1
    if name=='mode-reserved32':state.mode.reserved32=1
    if name=='over-limit':
        state=Status(mode=Mode(1,1,0,0,0),generation=42,expected_vcpus=9,phase=1)
    if name=='invalid-request':r.flags=1
    if name=='status-output-alias':
        arena=C.create_string_buffer(96);C.memmove(arena,C.byref(state),32)
        status_ptr=C.cast(arena,C.POINTER(Status));output_ptr=C.cast(arena,C.POINTER(Request));before=bytes(arena)
        rc=encode(C.byref(r),8,status_ptr,output_ptr);unchanged=bytes(arena)==before
    else:
        rc=encode(C.byref(r),8,C.byref(state),C.byref(o));unchanged=bytes(o)==before
    results.append({'case':name,'passed':rc==errno.EINVAL and unchanged})
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'command':command,'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [*sources,binary,Path(__file__)]},'scope':'Portable original source, not a kernel dispatcher or vCPU run'},indent=2)+'\n')
for r in results:
    if not r['passed']:print(r)
print(f"{sum(r['passed'] for r in results)}/{len(results)} management checks passed")
raise SystemExit(not all(r['passed'] for r in results))
