#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inspect actual zlib target outputs with declared native tools, without execution."""
import argparse
from pathlib import Path
import struct
import subprocess


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('example', 'shared', 'archive', 'pic-archive', 'nm', 'ar', 'objdump'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--machine', type=int, choices=[62, 183, 243], required=True)
    a = p.parse_args()
    for path, kinds in [(a.example, [2, 3]), (a.shared, [3])]:
        data = path.read_bytes()
        require(len(data) >= 64 and data[:6] == b'\x7fELF\x02\x01', 'ELF64 little endian required')
        kind, machine = struct.unpack_from('<HH', data, 16)
        require(kind in kinds and machine == a.machine, 'target ELF machine/type differs')
    names = ['adler32', 'compress', 'crc32', 'deflate', 'gzclose', 'gzlib', 'gzread', 'gzwrite',
             'infback', 'inffast', 'inflate', 'inftrees', 'trees', 'uncompr', 'zutil', 'zopen']
    for path, suffix in [(a.archive, '.o'), (a.pic_archive, '.pic.o')]:
        actual = subprocess.check_output([a.ar, 't', path], text=True).splitlines()
        require(actual == [n + suffix for n in names], 'original archive member order differs')
    symbols = subprocess.check_output([a.nm, '--format=posix', '--extern-only', '--defined-only', a.example], text=True)
    defined = {line.split()[0] for line in symbols.splitlines() if line.split()}
    require({'compress', 'uncompress', 'gzopen'} <= defined, 'actual upstream example must extract zlib APIs')
    require(not {'zopen', 'zdopen'} & defined, 'ordinary static consumer must not force unrelated BSD wrapper object')
    dynamic = subprocess.check_output([a.objdump, '--dynamic-syms', a.shared], text=True)
    versioned = {tuple(line.split()[-2:]) for line in dynamic.splitlines() if len(line.split()) >= 6 and line.split()[1] == 'g'}
    require(('FBSD_1.2', 'zopen') in versioned and ('FBSD_1.6', 'zdopen') in versioned, 'BSD wrapper versioned ABI differs')
    for version in ['ZLIB_1.2.4.0', 'ZLIB_1.2.12', 'ZLIB_1.3.2']:
        require(version in dynamic, 'original zlib symbol version missing: ' + version)
    print('target ABIs, original regular/PIC order, default upstream static extraction and versioned BSD ABI: passed')


if __name__ == '__main__':
    main()
