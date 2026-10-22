#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check actual compile-only CLI disassembly using an independent DIF decoder."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import struct
from dof_validation import validate_dof

out, obj, corpus = (Path(p).resolve() for p in sys.argv[1:])
assert all(p.is_relative_to('/usr/obj') for p in (out,obj,corpus)) and not out.exists()
out.mkdir(parents=True)
root = Path(__file__).resolve().parents[3]
header = root/'sys/cddl/contrib/opensolaris/uts/common/sys/dtrace.h'
opcodes = {int(value):name.lower() for name,value in re.findall(r'^#define\s+DIF_OP_(\w+)\s+(\d+)\b',header.read_text(),re.M)}
assert len(opcodes) > 70
binary = obj/'cddl/usr.sbin/dtrace/dtrace'
library = obj/'cddl/lib/libdtrace/libdtrace.so.2'
shim = out/'nodev.c'
shim.write_text('''#include <dlfcn.h>
#include <stdlib.h>
void *dtrace_open(int version, int flags, int *errp) {
 void *(*real_open)(int,int,int *) = dlsym(RTLD_NEXT,"dtrace_open");
 if (!real_open) abort();
 return real_open(version,flags|3,errp);
}
''')
subprocess.run(['/usr/bin/cc','-shared','-fPIC',str(shim),'-o',str(out/'nodev.so')],check=True)
env = dict(os.environ,LD_PRELOAD=str(out/'nodev.so'),LD_LIBRARY_PATH=':'.join(str(obj/p) for p in
    ('cddl/lib/libdtrace','cddl/lib/libctf','lib/libproc','lib/librtld_db')))
three = set('or xor and sll srl sra sub add mul sdiv udiv srem urem copys'.split())
two = set('not mov allocs'.split())
branches = set('ba be bne bg bgu bge bgeu bl blu ble bleu'.split())

def decode(text, expected_has_dif):
    blocks = []; seen = set(); operand_checks = 0
    for line in text.splitlines():
        if line.startswith('DIFO '):blocks.append([])
        if not re.match(r'^\d+:',line):continue
        match = re.fullmatch(r'(\d+): ([0-9a-f]{8})\s+(\w+)\s*(.*)',line)
        assert match, line
        offset, encoded, mnemonic, operands = match.groups()
        word = int(encoded,16); op = word >> 24
        assert blocks and int(offset) == len(blocks[-1]),line
        assert opcodes[op] == mnemonic,line
        r1,r2,rd = (word >> 16)&255,(word >> 8)&255,word&255
        registers = [int(v) for v in re.findall(r'%r(\d+)',operands.split('!')[0].split('=>')[0])]
        if mnemonic in three:
            assert registers == [r1,r2,rd],line;operand_checks += 1
        elif mnemonic in two:
            assert registers == [r1,rd],line;operand_checks += 1
        elif mnemonic in ('cmp','scmp'):
            assert registers == [r1,r2],line;operand_checks += 1
        elif mnemonic == 'tst':
            assert registers == [r1],line;operand_checks += 1
        elif mnemonic == 'ret':
            assert registers == [rd],line;operand_checks += 1
        elif mnemonic in branches:
            assert int(operands) == word&0xffffff,line;operand_checks += 1
        elif mnemonic in ('setx','sets'):
            index = re.search(r'\[(\d+)\]',operands)
            assert index and int(index.group(1)) == (word>>8)&0xffff and registers == [rd],line
            operand_checks += 1
        blocks[-1].append(word);seen.add(mnemonic)
    assert bool(blocks) == expected_has_dif and all(blocks)
    return dict(blocks=len(blocks),instructions=sum(map(len,blocks)),operand_checks=operand_checks,mnemonics=sorted(seen))

inputs = json.loads(corpus.read_text());assert all(r['passed'] for r in inputs)
results = []; references = []
for item in inputs:
    if not item['expected_compile']:continue
    name = item['case']
    reference = corpus.with_name(name+'.dof');references.append(reference)
    data = reference.read_bytes();validate_dof(data)
    endian = '<' if data[5] == 1 else '>'
    stride,count = struct.unpack_from(endian+'II',data,24)
    table = struct.unpack_from(endian+'Q',data,32)[0]
    reference_instructions = []
    for i in range(count):
        kind,alignment,flags,entry,start,size = struct.unpack_from(endian+'IIIIQQ',data,table+i*stride)
        if kind == 7:reference_instructions.append(list(struct.unpack_from(endian+str(size//4)+'I',data,start)))
    has_dif = bool(reference_instructions)
    # dt_cc.c constructs these constant/return DIFOs directly, bypassing
    # dt_as() and its -S output. Verify their exact shape, not an exemption
    # based solely on missing output.
    synthetic = {
        'aggregate-clear': [[0x25000001,0x23000001],[0x25000001,0x23000001]],
        'format-escaped-percent': [[0x23000000]],
    }
    if name in synthetic:
        assert reference_instructions == synthetic[name]
        has_dif = False
    command = [str(binary),'-e','-S','-x','nolibs','-n',item['source']]
    run = subprocess.run(command,cwd=out,env=env,capture_output=True,text=True,timeout=30)
    text = run.stdout+run.stderr
    (out/(name+'.txt')).write_text(text)
    try:
        assert run.returncode == 0 and 'LLVM Profile Error' not in text
        details = decode(text,has_dif);error = ''
    except (AssertionError,ValueError,KeyError) as exc:
        details = {};error = repr(exc)
    results.append(dict(case=name,source=item['source'],status=run.returncode,synthetic_dif_without_listing=name in synthetic,details=details,error=error,passed=not error))
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest()
    for p in (binary,library,header,corpus,Path(__file__).resolve(),Path(__file__).with_name('dof_validation.py').resolve(),shim,*references)},'scope':'compile-only -e -S; NODEV/NOSYS shim; no tracing'},indent=2)+'\n')
for r in results:
    if not r['passed']:print(json.dumps(r))
print('Disassembled',len(results),'programs;',sum(not r['passed'] for r in results),'failures')
raise SystemExit(not all(r['passed'] for r in results))
