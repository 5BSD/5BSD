#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production memory-layout object through a visibility adapter."""
from pathlib import Path
import ctypes as C
import errno,hashlib,json,os,random,subprocess,sys
out,obj=(Path(p).resolve() for p in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out,obj)) or out.exists():
    raise SystemExit('Use a new /usr/obj output and existing memory .pico object')
root=Path(__file__).resolve().parents[3]
source=root/'lib/libvmmapi/vmmapi_memory.c'
if not obj.is_file() or obj.stat().st_mtime_ns<source.stat().st_mtime_ns:
    raise SystemExit('Rebuild actual memory object first')
out.mkdir(parents=True)
adapter=out/'adapter.c'
adapter.write_text('''#include "vmmapi_memory.h"
int ht_layout(const size_t *s, size_t n, uint64_t low, uint64_t high,
    uint64_t guard, uint64_t limit, struct vmmapi_memory_layout *out) {
    return vmmapi_memory_layout_calculate(s,n,low,high,guard,limit,out);
}
int ht_segid(int id) { return vmmapi_devmem_segid_valid(id); }
int ht_first(void) { return VM_BOOTROM; }
int ht_end(void) { return VM_MEMSEG_END; }
''')
binary=out/'adapter.so'
command=['/usr/bin/cc','-shared','-fPIC','-fprofile-instr-generate','-I'+str(root/'lib/libvmmapi'),'-I'+str(root/'sys'),str(adapter),str(obj),'-o',str(binary)]
subprocess.run(command,check=True)
lib=C.CDLL(str(binary))
class Layout(C.Structure):
    _fields_=[(k,C.c_uint64) for k in ('guest_size','address_span','reservation_size')]
assert C.sizeof(C.c_size_t)==8
lib.ht_layout.argtypes=[C.POINTER(C.c_size_t),C.c_size_t,*([C.c_uint64]*4),C.POINTER(Layout)]
lib.ht_layout.restype=C.c_int
lib.ht_segid.argtypes=[C.c_int]
maximum=2**64-1
results=[]
def check(name,domains,low,high,guard,limit,null_input=False,null_output=False):
    array=(C.c_size_t*len(domains))(*domains)
    layout=Layout(0xa1,0xb2,0xc3);before=bytes(layout)
    # Independent arbitrary-precision reference: no wrapping at intermediate sums.
    guest=sum(domains)
    span=guest if guest<=low else high+guest-low
    reservation=span+2*guard
    if null_input or null_output or not domains or 0 in domains or high<low:
        expected=errno.EINVAL
    elif guest>maximum or span>maximum or reservation>maximum or reservation>limit:
        expected=errno.EOVERFLOW
    else:expected=0
    status=lib.ht_layout(None if null_input else array,len(domains),low,high,guard,limit,None if null_output else C.byref(layout))
    unchanged=bytes(layout)==before
    actual=(layout.guest_size,layout.address_span,layout.reservation_size)
    passed=status==expected and (unchanged if expected else actual==(guest,span,reservation))
    results.append({'case':name,'domains':domains,'low':low,'high':high,'guard':guard,'limit':limit,'expected_status':expected,'status':status,'actual':actual,'passed':passed})
for name,domains,low,high,guard,limit in [
    ('low-only',[4096],8192,2**32,4096,maximum),
    ('low-boundary',[4096,4096],8192,2**32,4096,maximum),
    ('high-start',[4096,4097],8192,2**32,4096,maximum),
    ('empty',[],0,0,0,maximum),('zero-domain',[4096,0],8192,2**32,0,maximum),
    ('reversed-hole',[4096],8192,4096,0,maximum),
    ('sum-wrap',[maximum,1],0,0,0,maximum),
    ('high-wrap',[4096],0,maximum,0,maximum),
    ('first-guard-wrap',[maximum],maximum,maximum,1,maximum),
    ('second-guard-wrap',[maximum-1],maximum,maximum,1,maximum),
    ('host-limit-exact',[4096],4096,4096,4096,12288),
    ('host-limit-short',[4096],4096,4096,4096,12287),
    ('max-exact',[maximum],maximum,maximum,0,maximum)]:
    check(name,domains,low,high,guard,limit)
check('null-domains',[4096],4096,4096,0,maximum,null_input=True)
check('null-layout',[4096],4096,4096,0,maximum,null_output=True)
rng=random.Random(0x5b5d)
for i in range(512):
    domains=[rng.randrange(1,2**rng.choice([16,32,63,64])) for _ in range(rng.randrange(1,9))]
    low=rng.choice([0,2**31,2**32,maximum]);high=rng.choice([low,maximum,2**32])
    guard=rng.choice([0,4096,2**32,maximum//2]);limit=rng.choice([maximum,2**32-1])
    check('generated-'+str(i),domains,low,high,guard,limit)
first,end=lib.ht_first(),lib.ht_end()
for value in [-2**31,-1,*range(0,end+2),2**31-1]:
    actual=bool(lib.ht_segid(value));expected=first<=value<end
    results.append({'case':'segment-'+str(value),'value':value,'passed':actual==expected})
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'command':command,'pid':os.getpid(),'seed':0x5b5d,'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (obj,source,adapter,binary,Path(__file__))},'scope':'Actual memory .pico; visibility adapter only; no VM operations'},indent=2)+'\n')
for r in results:
    if not r['passed']:print(r)
print(f"{sum(r['passed'] for r in results)}/{len(results)} layout checks passed")
raise SystemExit(not all(r['passed'] for r in results))
