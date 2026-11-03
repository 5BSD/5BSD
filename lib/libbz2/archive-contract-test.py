#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inspect declared target outputs with native LLVM tools; never execute them."""
import argparse
from pathlib import Path
import struct
import subprocess
import zlib


def elf(path, machine):
    data=path.read_bytes()
    if len(data)<64 or data[:6]!=b'\x7fELF\x02\x01':
        raise ValueError('little-endian ELF64 required: '+str(path))
    kind,actual=struct.unpack_from('<HH',data,16)
    if kind!=3 or actual!=machine:
        raise ValueError('target ELF ABI/type differs: '+str(path))
    return data


def compressed_dwarf(data):
    header = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    entries = [struct.unpack_from('<IIQQQQIIQQ', data, header[5] + i * header[10])
               for i in range(header[11])]
    strings = entries[header[12]]
    names = data[strings[4]:strings[4] + strings[5]]
    sections = [entry for entry in entries
                if names[entry[0]:names.index(0, entry[0])] == b'.debug_info']
    if len(sections) != 1 or not (sections[0][2] & 0x800):
        raise ValueError('original executable link requires compressed DWARF')
    entry = sections[0]
    payload = data[entry[4]:entry[4] + entry[5]]
    kind, reserved, size, alignment = struct.unpack_from('<IIQQ', payload)
    if kind != 1 or reserved != 0 or not alignment:
        raise ValueError('invalid ELF zlib compression header')
    if len(zlib.decompress(payload[24:])) != size:
        raise ValueError('compressed DWARF size differs')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ['consumer','shared','program','archive','nm','ar']:
        parser.add_argument('--'+key,type=Path,required=True)
    parser.add_argument('--machine',type=int,required=True,choices=[62,183,243])
    args=parser.parse_args()
    elf(args.consumer,args.machine)
    elf(args.shared,args.machine)
    compressed_dwarf(elf(args.program,args.machine))
    result=subprocess.run([str(args.nm),'--format=posix','--extern-only','--defined-only',str(args.consumer)],check=True,text=True,capture_output=True)
    selected={line.split()[0] for line in result.stdout.splitlines() if line.split() and line.split()[0].startswith('BZ2_')}
    if selected!={'BZ2_rNums'}:
        raise ValueError('consumer symbol contract differs: '+str(sorted(selected)))
    result=subprocess.run([str(args.ar),'t',str(args.archive)],check=True,text=True,capture_output=True)
    expected=[name+'.o' for name in ['bzlib','blocksort','compress','crctable','decompress','huffman','randtable']]
    if result.stdout.splitlines()!=expected:
        raise ValueError('original seven-member archive order differs')
    print('PASS target ELF ABIs, consumer retained symbol and original archive member order and compressed DWARF; no target execution')


if __name__=='__main__':
    main()
