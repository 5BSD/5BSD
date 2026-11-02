#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise ordered NEEDED checks using explicit real ELF oracle inputs.

Only private negative fixtures are modified. Original artifacts remain untouched;
no modified output is used as a build candidate or a parity reference.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
spec = importlib.util.spec_from_file_location(
    'elf_artifact_check', Path(__file__).with_name('elf-artifact-check.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def reordered_fixture(source, output):
    data = bytearray(source.read_bytes())
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('negative fixture requires ELF64 little-endian input')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', data, 54)
    if phentsize != 56 or phoff + phnum * phentsize > len(data):
        raise ValueError('invalid program header bounds')
    dynamic = []
    for i in range(phnum):
        kind, _, offset, _, _, size, _, _ = struct.unpack_from(
            '<IIQQQQQQ', data, phoff + i * phentsize)
        if kind == 2:  # PT_DYNAMIC
            if offset + size > len(data) or size % 16:
                raise ValueError('invalid dynamic segment bounds')
            dynamic.append((offset, size))
    if len(dynamic) != 1:
        raise ValueError('exactly one dynamic segment required')
    offset, size = dynamic[0]
    needed = []
    for pos in range(offset, offset + size, 16):
        tag, value = struct.unpack_from('<qQ', data, pos)
        if tag == 0:
            break
        if tag == 1:
            needed.append((pos, value))
    if len(needed) < 2 or needed[0][1] == needed[1][1]:
        raise ValueError('at least two distinct NEEDED entries required')
    struct.pack_into('<Q', data, needed[0][0] + 8, needed[1][1])
    struct.pack_into('<Q', data, needed[1][0] + 8, needed[0][1])
    output.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('program', 'shared', 'readelf', 'objcopy', 'work'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--soname', required=True)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=False)
    results = []
    for kind, original in (('program', args.program), ('shared', args.shared)):
        original_hash = checker.sha(original)
        scratch = args.work / (kind + '-scratch')
        scratch.mkdir()
        candidate = args.work / (kind + '-reordered.elf')
        reordered_fixture(original, candidate)
        compare = checker.compare_program if kind == 'program' else checker.compare_shared
        extra = () if kind == 'program' else (args.soname,)
        positive = compare(args.readelf, args.objcopy, original, original, *extra, scratch)
        assert positive['needed_order_equal'] and positive['byte_identical']
        # Confirm the negative changes only order in the parsed dynamic metadata.
        argv = [args.readelf, '-h', '-l', '-d', '-W', '--dyn-syms', '--version-info']
        before = checker.parse_program(checker.run(argv + [original]), program=kind == 'program')
        after = checker.parse_program(checker.run(argv + [candidate]), program=kind == 'program')
        assert before['needed_order'] != after['needed_order']
        assert {k: v for k, v in before.items() if k != 'needed_order'} == {
            k: v for k, v in after.items() if k != 'needed_order'}
        try:
            compare(args.readelf, args.objcopy, candidate, original, *extra, scratch)
        except ValueError as error:
            if 'needed_order' not in str(error):
                raise
            rejected = str(error)
        else:
            raise AssertionError(kind + ': reordered NEEDED was incorrectly accepted')
        assert checker.sha(original) == original_hash
        results.append({'kind': kind, 'original': str(original),
                        'original_sha256': original_hash,
                        'negative_fixture_sha256': checker.sha(candidate),
                        'positive': 'PASS', 'negative': 'PASS', 'rejection': rejected})
    report = {'checker_sha256': checker.sha(Path(checker.__file__)),
              'test_sha256': checker.sha(Path(__file__)),
              'readelf_sha256': checker.sha(args.readelf),
              'objcopy_sha256': checker.sha(args.objcopy), 'checks': results}
    (args.work / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': 'PASS', 'checks': results}, indent=2))


if __name__ == '__main__':
    main()
