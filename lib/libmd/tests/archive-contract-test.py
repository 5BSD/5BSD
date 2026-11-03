#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inspect the real libmd archives and digest driver without target execution."""
import argparse
from pathlib import Path
import struct
import subprocess


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('driver', 'shared', 'archive', 'pic-archive', 'nm', 'ar'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--machine', type=int, choices=[62, 183, 243], required=True)
    p.add_argument('--optimized', choices=['true', 'false'], required=True)
    a = p.parse_args()
    base = ['md4c', 'md5c', 'md4hl', 'md5hl', 'rmd160c', 'rmd160hl', 'sha0c', 'sha0hl',
            'sha1c', 'sha1hl', 'sha224hl', 'sha256c', 'sha256hl', 'sha384hl', 'sha512c',
            'sha512hl', 'sha512t224hl', 'sha512t256hl', 'skein', 'skein_block',
            'skein256hl', 'skein512hl', 'skein1024hl']
    extra = []
    if a.optimized == 'true':
        if a.machine == 62:
            extra = ['md5block', 'md5dispatch', 'sha1block', 'sha1dispatch', 'skein_block_asm']
        elif a.machine == 183:
            extra = ['md5block', 'sha1block', 'sha1dispatch', 'sha256c_arm64', 'sha512c_arm64']
    for path, suffix in [(a.archive, '.o'), (a.pic_archive, '.pic.o')]:
        members = subprocess.check_output([a.ar, 't', path], text=True).splitlines()
        require(members == [n + suffix for n in base + extra], 'original member order/selection differs')
    for path, kinds in [(a.driver, [2, 3]), (a.shared, [3])]:
        data = path.read_bytes()
        require(len(data) >= 64 and data[:6] == b'\x7fELF\x02\x01', 'ELF64 little endian required')
        kind, machine = struct.unpack_from('<HH', data, 16)
        require(kind in kinds and machine == a.machine, 'target ELF machine/type differs')
    symbols = subprocess.check_output([a.nm, '--format=posix', '--extern-only', '--defined-only', a.driver], text=True)
    defined = {line.split()[0] for line in symbols.splitlines() if line.split()}
    require({'MD5Data', 'MD5Init', 'MD5Update', 'MD5Final'} <= defined, 'real MD5 driver failed to extract its API')
    require(not {'MD4Data', 'RIPEMD160_Data', 'SHA512_Data', 'SKEIN1024_Data'} & defined,
            'static driver forced unrelated digest archive members')
    print('libmd archive variants/order, target ABI and real digest-driver lazy extraction: passed')


if __name__ == '__main__':
    main()
