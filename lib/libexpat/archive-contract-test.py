#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inspect actual BSD XML target outputs without executing foreign programs."""
import argparse
from pathlib import Path
import struct
import subprocess


def require(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'pic-archive', 'shared', 'static-consumer', 'shared-consumer', 'ar', 'nm'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--machine', type=int, choices=[62, 183, 243], required=True)
    args = parser.parse_args()
    for path, kinds in [(args.shared, [3]), (args.static_consumer, [2, 3]), (args.shared_consumer, [2, 3])]:
        data = path.read_bytes()
        require(data[:6] == b'\x7fELF\x02\x01' and len(data) >= 64, 'ELF64 little endian required')
        kind, machine = struct.unpack_from('<HH', data, 16)
        require(kind in kinds and machine == args.machine, 'target machine/type differs')
    members = ['random_arc4random_buf', 'xcs', 'xmlparse', 'xmlrole', 'xmltok']
    for path, suffix in [(args.archive, '.o'), (args.pic_archive, '.pic.o')]:
        actual = subprocess.check_output([args.ar, 't', path], text=True).splitlines()
        require(actual == [name + suffix for name in members], 'original five-member order differs')
    symbols = subprocess.check_output([args.nm, '--format=posix', '--extern-only', '--defined-only', args.static_consumer], text=True)
    defined = {line.split()[0] for line in symbols.splitlines() if line.split()}
    require({'XML_ParserCreate', 'XML_ParserCreateNS', 'XML_Parse', 'XML_ParserFree'} <= defined,
            'real parser consumer did not extract the default archive API')
    print('BSD XML target ABI, original archive order and static extraction: passed')


if __name__ == '__main__':
    main()
