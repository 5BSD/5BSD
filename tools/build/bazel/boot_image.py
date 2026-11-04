# SPDX-License-Identifier: BSD-2-Clause
"""Declared zero, padding, alignment and concatenation operations used by BIOS boot recipes."""
import argparse
from pathlib import Path


def image_bytes(operation, sources, size):
    if operation == 'zero':
        if sources or size < 1:
            raise ValueError('zero requires no inputs and a positive size')
        return bytes(size)
    if operation in ('pad', 'check'):
        if len(sources) != 1 or size < 1:
            raise ValueError('pad/check requires one input and a positive size')
        if len(sources[0]) > size:
            raise ValueError('boot image exceeds its declared size limit')
        return sources[0] if operation == 'check' else sources[0] + bytes(size - len(sources[0]))
    if operation == 'align':
        if len(sources) != 1 or size < 1:
            raise ValueError('align requires one input and a positive block size')
        return sources[0] + bytes((-len(sources[0])) % size)
    if operation == 'concat':
        if len(sources) < 2 or size != 0:
            raise ValueError('concat requires at least two ordered inputs and no size')
        return b''.join(sources)
    raise ValueError('unknown boot image operation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operation', required=True, choices=['zero', 'pad', 'concat', 'check', 'align'])
    parser.add_argument('--size', type=int, default=0)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('sources', nargs='*', type=Path)
    args = parser.parse_args()
    try:
        payload = image_bytes(args.operation, [p.read_bytes() for p in args.sources], args.size)
    except ValueError as error:
        parser.error(str(error))
    args.output.write_bytes(payload)


if __name__ == '__main__':
    main()
