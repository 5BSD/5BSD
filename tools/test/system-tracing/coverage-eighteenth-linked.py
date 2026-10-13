#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Verify this round's SDT sites in the final linked amd64 kernel ELF executable."""
from pathlib import Path
import json,re,struct
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-eighteenth-validation');K=Path('/usr/obj/usr/src/amd64.amd64/sys/GENERIC-NODEBUG/kernel')
data=K.read_bytes();assert data[:6]==b'\x7fELF\x02\x01';assert struct.unpack_from('<HH',data,16)==(2,62)
offset=struct.unpack_from('<Q',data,40)[0];size,count,strings=struct.unpack_from('<HHH',data,58)
sections=[struct.unpack_from('<IIQQQQIIQQ',data,offset+i*size) for i in range(count)]
def body(i):
 s=sections[i];return data[s[4]:s[4]+s[5]]
def string(b,n):return b[n:b.index(b'\0',n)].decode()
names={string(body(strings),s[0]):i for i,s in enumerate(sections)}
symsec=sections[names['.symtab']];symbols=[]
symdata=body(names['.symtab']);strdata=body(symsec[6])
for n in range(0,symsec[5],symsec[9]):
 name,info,other,section,value,size=struct.unpack_from('<IBBHQQ',symdata,n)
 symbols.append((string(strdata,name),value))
raw=body(names['set_sdt_tracepoint_set']);assert len(raw)%32==0
sites=[struct.unpack_from('<QQQ',raw,n) for n in range(0,len(raw),32)]
def executable(addr,length):
 matches=[i for i,s in enumerate(sections) if s[2]&4 and s[3]<=addr and addr+length<=s[3]+s[5]];assert len(matches)==1,hex(addr)
 i=matches[0];off=addr-sections[i][3];return body(i)[off:off+length]
inv=json.loads((S/'tools/test/system-tracing/coverage-eighteenth.json').read_text());results=[]
for p in inv['probes']:
 pattern=re.compile(r'(?:^|\.)sdt_sdt___'+re.escape(p['name'].replace('-','__'))+r'(?:\.[0-9]+)?$')
 defs=[value for name,value in symbols if pattern.search(name)];assert defs,p['name'];count=0
 for address in defs:
  matches=[(patch,target) for probe,patch,target in sites if probe==address];assert matches,p['name']
  for patch,target in matches:
   assert executable(patch,5)==bytes.fromhex('660f1f0400'),p['name'];executable(target,1);count+=1
 results.append(dict(contract=p['name'],executable_sites=count,status=0))
 print(p['name'],count,'linked sites',flush=True)
(O/'linked-site-results.json').write_text(json.dumps(results,indent=2)+'\n')
