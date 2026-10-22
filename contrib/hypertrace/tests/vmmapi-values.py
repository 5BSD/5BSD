#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Actual libvmmapi value APIs: no VM opens, ioctls, mappings or execution."""
from pathlib import Path
import ctypes as C
import errno,hashlib,json,random,sys
out,binary=(Path(p).resolve() for p in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out,binary)) or out.exists():
    raise SystemExit('Use new /usr/obj output and actual library')
out.mkdir(parents=True)
lib=C.CDLL(str(binary))
lib.vm_distribute_memory_domains.argtypes=[C.c_size_t,C.c_size_t,C.c_size_t,C.POINTER(C.c_size_t),C.c_size_t]
lib.vm_distribute_memory_domains.restype=C.c_int
class Result(C.Structure):
    _fields_=[(k,C.c_uint16) for k in ('version','size','operation','flags')]+[(k,C.c_uint64) for k in ('gpa','length','identity','map_generation','dirty_generation','bitmap_offset','bitmap_bytes')]+[('reserved8',C.c_uint8*16)]
assert C.sizeof(Result)==80
lib.vm_dirty_log_result_validate.argtypes=[C.POINTER(Result),C.c_size_t]
lib.vm_dirty_log_result_validate.restype=C.c_int
results=[]
def record(name,passed,**detail): results.append(dict(case=name,passed=bool(passed),**detail))
rng=random.Random(0x5b5d)
sentinel=0xdeadbeef
for n in range(256):
    domains=rng.randrange(1,65); granule=rng.choice([1,4096,2**21,2**30])
    units=rng.randrange(domains,domains+10000);total=units*granule
    sizes=(C.c_size_t*(domains+2))(*([sentinel]*(domains+2)))
    status=lib.vm_distribute_memory_domains(total,domains,granule,sizes,domains)
    values=list(sizes)[:domains]
    record('distribution-'+str(n),status==0 and sum(values)==total and min(values)>0 and
        all(v%granule==0 for v in values) and max(values)-min(values)<=granule and
        list(sizes)[domains:]==[sentinel,sentinel],total=total,domains=domains,granule=granule)
for name,total,domains,granule,capacity,null in [
    ('zero-total',0,2,4096,2,False),('zero-domains',8192,0,4096,2,False),
    ('zero-granule',8192,2,0,2,False),('short-capacity',8192,2,4096,1,False),
    ('misaligned',8193,2,4096,2,False),('too-few-units',4096,2,4096,2,False),
    ('null-output',8192,2,4096,2,True)]:
    sizes=(C.c_size_t*4)(*([sentinel]*4))
    status=lib.vm_distribute_memory_domains(total,domains,granule,None if null else sizes,capacity)
    record(name,status==errno.EINVAL and list(sizes)==[sentinel]*4,status=status)
def valid(pages=1,operation=2):
    return Result(version=1,size=80,operation=operation,gpa=0,length=pages*4096,
        identity=1,map_generation=1,dirty_generation=1,bitmap_offset=80,bitmap_bytes=(pages+7)//8)
def check(name,result,size,expected):
    before=None if result is None else bytes(result)
    status=lib.vm_dirty_log_result_validate(None if result is None else C.byref(result),size)
    record(name,status==expected and (result is None or bytes(result)==before),status=status,expected=expected)
for pages in (1,7,8,9,4096,8*1024*1024):
    for operation in (2,3):
        r=valid(pages,operation);check('valid-%d-%d'%(pages,operation),r,80+r.bitmap_bytes,0)
check('null-result',None,81,errno.EINVAL)
for field,value in [('version',0),('version',2),('size',79),('size',81),('operation',0),('operation',1),('operation',4),('flags',1),('gpa',1),('length',0),('length',4097),('identity',0),('map_generation',0),('dirty_generation',0),('bitmap_offset',79),('bitmap_offset',81),('bitmap_bytes',0),('bitmap_bytes',2)]:
    r=valid();setattr(r,field,value);check('invalid-%s-%d'%(field,value),r,81,errno.EINVAL)
for i in range(16):
    r=valid();r.reserved8[i]=1;check('reserved-%d'%i,r,81,errno.EINVAL)
for size in (0,79,80,82,2**32):check('buffer-size-%d'%size,valid(),size,errno.EINVAL)
r=valid(8*1024*1024+1);check('bitmap-limit',r,80+r.bitmap_bytes,errno.EINVAL)
r=valid(2);r.gpa=2**64-4096;check('address-wrap',r,81,errno.EINVAL)
r=valid();r.gpa=2**64-4096;check('address-upper-bound',r,81,0)
lib.vm_parse_memsize.argtypes=[C.c_char_p,C.POINTER(C.c_size_t)]
lib.vm_parse_memsize.restype=C.c_int
for text,expected in [('0',0),('1',2**20),('1024',2**30),('1048575',1048575*2**20),
    ('1048576',1048576),('0x10',16*2**20),('010',8*2**20),(' 2',2*2**20),
    ('+2',2*2**20),('1k',1024),('2M',2*2**20),('3g',3*2**30),('4GB',4*2**30),
    ('1t',2**40),('1p',2**50),('1e',2**60),('18446744073709551615',2**64-1),
    ('',None),(' ',None),('bogus',None),('1x',None),('1kbextra',None),
    ('-1',None),(' -2',None),('-18446744073709551615',None),
    ('18446744073709551616',None),('99999999999999999999999999',None),
    ('16e',None),('18446744073709551615k',None)]:
    value=C.c_size_t(sentinel)
    status=lib.vm_parse_memsize(text.encode(),C.byref(value))
    record('memory-size-'+text,(status==0 and value.value==expected) if expected is not None else
        (status==-1 and value.value==sentinel),input=text,status=status,value=value.value,expected=expected)
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'binary':str(binary),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'seed':0x5b5d,'scope':'Only public value APIs; no kernel interaction'},indent=2)+'\n')
for r in results:
    if not r['passed']:print(r)
print(f"{sum(r['passed'] for r in results)}/{len(results)} value checks passed")
raise SystemExit(not all(r['passed'] for r in results))
