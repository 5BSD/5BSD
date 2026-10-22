#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Render synthetic records through actual libdtrace; never consume live traces."""
import ctypes as C
import hashlib
import json
import math
import random
from pathlib import Path
import struct
import sys
import histogram_properties

out,binary=(Path(x).resolve() for x in sys.argv[1:])
if not out.is_relative_to('/usr/obj') or not binary.is_relative_to('/usr/obj') or out.exists():
    raise SystemExit('Use a new /usr/obj output and built library')
out.mkdir(parents=True)
lib=C.CDLL(str(binary)); libc=C.CDLL(None)
class Record(C.Structure):
    _fields_=[('action',C.c_uint32),('size',C.c_uint32),('offset',C.c_uint32),
        ('alignment',C.c_uint16),('format',C.c_uint16),('arg',C.c_uint64),('uarg',C.c_uint64)]
lib.dtrace_open.argtypes=[C.c_int,C.c_int,C.POINTER(C.c_int)];lib.dtrace_open.restype=C.c_void_p
lib.dtrace_close.argtypes=[C.c_void_p]
lib.dtrace_printf_create.argtypes=[C.c_void_p,C.c_char_p];lib.dtrace_printf_create.restype=C.c_void_p
lib.dt_printf_destroy.argtypes=[C.c_void_p]
lib.dtrace_fprintf.argtypes=[C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p,C.POINTER(Record),C.c_uint,C.c_void_p,C.c_size_t]
lib.dtrace_errno.argtypes=[C.c_void_p]
lib.dtrace_errmsg.argtypes=[C.c_void_p,C.c_int];lib.dtrace_errmsg.restype=C.c_char_p
libc.tmpfile.restype=C.c_void_p
for name in ('fflush','fclose','rewind'):
    getattr(libc,name).argtypes=[C.c_void_p]
libc.ftell.argtypes=[C.c_void_p];libc.ftell.restype=C.c_long
libc.fread.argtypes=[C.c_void_p,C.c_size_t,C.c_size_t,C.c_void_p];libc.fread.restype=C.c_size_t
cases=[
 ('signed','%d',[struct.pack('<i',-42)],'-42'),
 ('unsigned','%u',[struct.pack('<I',0xffffffff)],'4294967295'),
 ('wide','%lld',[struct.pack('<q',-0x100000000)],'-4294967296'),
 ('hex','%#08x',[struct.pack('<I',255)],'0x0000ff'),
 ('octal','%#o',[struct.pack('<I',8)],'010'),
 ('character','%c',[struct.pack('<i',65)],'A'),
 ('string','%s',[b'hello\0'],'hello'),
 ('precision','%.3s',[b'abcdef\0'],'abc'),
 ('width','%*d',[struct.pack('<i',5),struct.pack('<i',12)],'   12'),
 ('left-width','%*d',[struct.pack('<i',-5),struct.pack('<i',12)],'12   '),
 ('dynamic-precision','%.*s',[struct.pack('<i',3),b'abcdef\0'],'abc'),
 ('mixed','x=%d %s %%',[struct.pack('<i',7),b'ok\0'],'x=7 ok %'),
 ('literal','ready %%',[],'ready %'),
 ('missing-record','%d',[],None),
 ('short-buffer','%d',[struct.pack('<i',7)],None),
 ('bad-offset','%d',[struct.pack('<i',7)],None),
 ('misaligned','%d',[struct.pack('<i',7)],None),
]
cases += [
    ('average-basic','%llu',[struct.pack('<QQ',4,40)],'10'),
    ('average-empty','%llu',[struct.pack('<QQ',0,0)],'0'),
    ('average-short','%llu',[struct.pack('<Q',1)],None),
    ('stddev-empty','%llu',[struct.pack('<QQQQ',0,0,0,0)],'0'),
    ('stddev-short','%llu',[struct.pack('<Q',1)],None),
]
rng = random.Random(0x5b5d)
for sample in range(128):
    values = [rng.randrange(-(1 << 45), 1 << 45) for _ in range(1 + sample % 16)]
    count, total, squares = len(values), sum(values), sum(v*v for v in values)
    # Exact wider-integer oracle with C's truncation toward zero for the mean.
    mean_magnitude = abs(total) // count
    expected = math.isqrt(squares // count - mean_magnitude * mean_magnitude)
    payload = struct.pack('<QQQQ', count, total & ((1 << 64)-1),
        squares & ((1 << 64)-1), squares >> 64)
    cases.append(('stddev-reference-'+str(sample),'%llu',[payload],str(expected)))
for name, bins, expected in [
    ('empty', {}, {-1:0, 0:0, 1:0}),
    ('positive', {64:3}, {0:0, 1:3, 2:0}),
    ('negative', {62:-4}, {-2:0, -1:-4, 0:0}),
    ('mixed', {62:-3,64:5}, {-2:0,-1:-3,0:0,1:5,2:0}),
    ('lowest', {0:3}, {-(1<<62):3, -(1<<61):0}),
    ('highest', {126:7}, {1<<61:0, 1<<62:7}),
]:
    values = [bins.get(i,0) for i in range(127)]
    cases.append(('quantize-'+name,'%d',[struct.pack('<127q',*values)],expected))
cases.append(('quantize-short','%d',[struct.pack('<q',1)],None))
# Linear histogram: base 10, three levels, step 2; five count buckets.
linear_header = (2 << 48) | (3 << 32) | 10
for name, counts, expected in [
    ('empty',[0,0,0,0,0],{'< 10':0,10:0,12:0}),
    ('underflow',[4,0,0,0,0],{'< 10':4,10:0}),
    ('overflow',[0,0,0,0,7],{14:0,'>= 16':7}),
    ('middle',[0,0,3,0,0],{10:0,12:3,14:0}),
    ('negative',[0,0,-3,0,0],{10:0,12:-3,14:0}),
    ('mixed',[-2,3,0,-1,4],{'< 10':-2,10:3,12:0,14:-1,'>= 16':4}),
]:
    payload = struct.pack('<Q',linear_header) + struct.pack('<5q',*counts)
    cases.append(('lquantize-'+name,'%d',[payload],expected))
cases += [
    ('lquantize-short-header','%d',[b'bad'],None),
    ('lquantize-short-counts','%d',[struct.pack('<Qq',linear_header,1)],None),
]
# Log-linear histogram: factor 2, orders 1..2, two steps per order.
# The buckets are <2, 2, 4 and >=8; expectations are explicit.
log_header = (2 << 48) | (1 << 32) | (2 << 16) | 2
for name, counts, expected in [
    ('empty',[0,0,0,0],{'< 2':0,2:0}),
    ('underflow',[4,0,0,0],{'< 2':4,2:0}),
    ('overflow',[0,0,0,7],{4:0,'>= 8':7}),
    ('middle',[0,0,3,0],{2:0,4:3,'>= 8':0}),
    ('negative',[0,-3,0,0],{'< 2':0,2:-3,4:0}),
    ('mixed',[-2,3,-1,4],{'< 2':-2,2:3,4:-1,'>= 8':4}),
]:
    payload = struct.pack('<Q4q',log_header,*counts)
    cases.append(('llquantize-'+name,'%d',[payload],expected))
# Decimal scale exercises unit steps followed by ten-unit steps.
labels = ['< 1'] + list(range(1,10)) + list(range(10,100,10)) + ['>= 100']
counts = list(range(1,21))
payload = struct.pack('<Q20q',(10 << 48) | (1 << 16) | 10,*counts)
cases.append(('llquantize-decimal','%d',[payload],dict(zip(labels,counts))))
# Highest supported power boundary: rendering must not compute unused 2^63.
payload = struct.pack('<Q4q',(2 << 48) | (60 << 32) | (61 << 16) | 2,1,2,3,4)
cases.append(('llquantize-high-power','%d',[payload],
    {'< '+str(1<<60):1,1<<60:2,1<<61:3,'>= '+str(1<<62):4}))
# Steps may divide a higher power without being a power themselves.
labels = ['< 1'] + list(range(1,10)) + list(range(10,100,5)) + ['>= 100']
counts = list(range(1,len(labels)+1))
payload = struct.pack('<Q',(10 << 48) | (1 << 16) | 20) + struct.pack('<'+str(len(counts))+'q',*counts)
cases.append(('llquantize-power-divisor','%d',[payload],dict(zip(labels,counts))))
cases.append(('llquantize-short-header','%d',[b'bad'],None))
for name, factor, low, high, steps in [
    ('factor-zero',0,1,2,2),
    ('factor-one',1,1,2,2),
    ('equal-orders',2,2,2,2),
    ('reversed-orders',2,3,2,2),
    ('zero-steps',2,1,2,0),
    ('too-few-steps',3,1,2,2),
]:
    header = (factor << 48) | (low << 32) | (high << 16) | steps
    cases.append(('llquantize-'+name,'%d',[struct.pack('<Q4q',header,0,0,0,0)],None))
property_cases, property_groups = histogram_properties.build_cases()
cases.extend(property_cases)
results=[]
for name,fmt,values,expected in cases:
    error=C.c_int();h=lib.dtrace_open(3,3,C.byref(error));assert h
    formatting=None;fp=None
    try:
        formatting=lib.dtrace_printf_create(h,fmt.encode());assert formatting
        fp=libc.tmpfile();assert fp
        payload=bytearray();records=(Record*max(1,len(values)))()
        for i,value in enumerate(values):
            while len(payload)%8:payload.append(0)
            alignment = len(value) if len(value) in (1,2,4,8) else 1
            action = (0x704 if name.startswith('average-') else
                0x706 if name.startswith('stddev-') else
                0x707 if name.startswith('quantize-') else
                0x708 if name.startswith('lquantize-') else
                0x709 if name.startswith('llquantize-') else 3)
            records[i]=Record(action,len(value),len(payload),alignment,0,0,0)
            payload.extend(value)
        payload.extend(b'\0'*8)
        data=C.create_string_buffer(bytes(payload));length=len(payload)
        if name=='short-buffer':length=2
        if name=='bad-offset':records[0].offset=length+1
        if name=='misaligned':
            assert C.addressof(data)%4==0
            records[0].offset=1;records[0].alignment=4
        rc=lib.dtrace_fprintf(h,fp,formatting,None,records,len(values),data,length)
        diagnostic=lib.dtrace_errmsg(h,lib.dtrace_errno(h)).decode(errors='replace') if rc<0 else ''
        assert libc.fflush(fp)==0
        size=libc.ftell(fp);assert 0<=size<1024*1024
        libc.rewind(fp);output=C.create_string_buffer(size+1)
        assert libc.fread(output,1,size,fp)==size
        text=output.raw[:size].decode()
        rendered = text
        if isinstance(expected, dict):
            rendered = {}
            for line in text.splitlines():
                if '|' in line:
                    fields = line.split()
                    label = ' '.join(fields[:2]) if fields[0] in ('<','>=') else int(fields[0])
                    count = int(fields[-1])
                    assert label not in rendered
                    rendered[label] = count
        passed=(rc>=0 and rendered==expected) if expected is not None else (rc==-1 and bool(diagnostic))
        results.append({'case':name,'format':fmt,'expected':expected,'actual':text,
            'parsed_output':rendered,'returncode':rc,'diagnostic':diagnostic,'passed':passed})
    finally:
        if fp:libc.fclose(fp)
        if formatting:lib.dt_printf_destroy(formatting)
        lib.dtrace_close(h)
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (binary,Path(__file__),Path(histogram_properties.__file__))},'scope':'Synthetic-record rendering via dtrace_fprintf; NODEV/NOSYS; temporary output streams only'},indent=2)+'\n')
relations = histogram_properties.check_relations(results, property_groups)
(out/'properties.json').write_text(json.dumps({'seed':histogram_properties.SEED,
    'groups':relations},indent=2)+'\n')
failed=[r for r in results if not r['passed']] + [r for r in relations if not r['passed']]
for r in failed:print(json.dumps(r))
if failed:raise SystemExit(1)
print('PASS:',len(results),'actual-library record formatting cases')
