#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Verify ELF64 DOF provider names, argument counts and real probe offsets."""
from pathlib import Path
import struct,json,sys

def elf_sections(path):
    b=path.read_bytes();assert b[:5]==b'\x7fELF\x02',path
    e='<' if b[5]==1 else '>'
    off=struct.unpack_from(e+'Q',b,40)[0]
    size,count,strings=struct.unpack_from(e+'HHH',b,58)
    secs=[struct.unpack_from(e+'IIQQQQIIQQ',b,off+i*size) for i in range(count)]
    tab=secs[strings];names=b[tab[4]:tab[4]+tab[5]]
    return {names[s[0]:].split(b'\0',1)[0].decode():b[s[4]:s[4]+s[5]] for s in secs}

def dof_probes(b):
    result=[];base=0
    while base<len(b):
        if b[base:base+4]!=b'\x7fDOF':
            base+=1;continue
        d=b[base:];e='<' if d[5]==1 else '>'
        secsize,nsec=struct.unpack_from(e+'II',d,24);secoff,loadsz,filesz=struct.unpack_from(e+'QQQ',d,32)
        assert filesz<=len(d) and filesz>0
        secs=[struct.unpack_from(e+'IIIIQQ',d,secoff+i*secsize) for i in range(nsec)]
        for sec in secs:
            if sec[0]!=15:continue
            strings,probes,args,offsets,name=struct.unpack_from(e+'IIIII',d,sec[4])
            st=secs[strings];tab=d[st[4]:st[4]+st[5]]
            def string(idx):return tab[idx:].split(b'\0',1)[0].decode()
            pr=secs[probes];assert pr[3]>=48
            for pos in range(pr[4],pr[4]+pr[5],pr[3]):
                fields=struct.unpack_from(e+'QIIIIIIBBHIHHI',d,pos)
                result.append(dict(provider=string(name),function=string(fields[1]),name=string(fields[2]).replace('__','-'),argc=fields[7],offsets=fields[9],enabled_offsets=fields[11]))
        base+=filesz
    return result

def main():
    root=Path(sys.argv[1] if len(sys.argv)>1 else '/usr/obj/5bsd-dtrace-20-validation')
    inventory=json.loads(Path('/usr/src/tools/test/system-tracing/coverage-fourth.json').read_text())
    results=[]
    for component,binary,provider in [('lib_libfetch','libfetch.so.6','fetchio'),('lib_libarchive','libarchive.so.7','archiveio'),('lib_libthr','libthr.so.3','threadwait'),('bin_cp','cp','cpcopy'),('usr.bin_xinstall','xinstall','installcopy'),('lib_libc','libc.so.7','semwait')]:
        on=root/'base'/(component+'-hooks')/binary
        off=root/'base'/(component+'-nohooks')/binary
        probes=dof_probes(elf_sections(on).get('.SUNW_dof',b''))
        disabled=dof_probes(elf_sections(off).get('.SUNW_dof',b''))
        for wanted in [p for p in inventory['probes'] if p['provider']==provider+'*']:
            matches=[p for p in probes if p['provider']==provider and p['name']==wanted['name']]
            assert matches,(on,wanted)
            assert all(p['argc']==len(wanted['types']) and p['offsets']>0 and p['enabled_offsets']>0 for p in matches),matches
        assert not any(p['provider']==provider for p in disabled),off
        results.append(dict(binary=str(on),provider=provider,probes=probes,disabled_provider_absent=True))
        print(provider+': linked DOF call sites and disabled absence PASS')
    (root/'dof-results.json').write_text(json.dumps(results,indent=2)+'\n')

if __name__=='__main__':main()
