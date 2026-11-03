#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check exact same-file definition selection using explicit ELF build tools.

ELF permits distinct symbol entries with the same name. The fixture gives a
strong and a weak object different sections and payloads, then aliases their
raw ELF names. Selection must preserve the strong entry's section, value and
size regardless of symbol order. This cannot be checked by name matching alone.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess


def read_elf(path):
    data = bytearray(path.read_bytes())
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 62:
        raise ValueError('fixture requires little-endian AMD64 ELF64')
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, string_index = struct.unpack_from('<HHH', data, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * size)
                for i in range(count)]

    def string(table, start):
        return bytes(table[start:table.index(0, start)]).decode()

    entry = sections[string_index]
    strings = data[entry[4]:entry[4] + entry[5]]
    names = [string(strings, section[0]) for section in sections]
    table = sections[names.index('.symtab')]
    entry = sections[table[6]]
    strings = data[entry[4]:entry[4] + entry[5]]
    symbols = []
    for i in range(table[5] // table[9]):
        position = table[4] + i * table[9]
        entry = struct.unpack_from('<IBBHQQ', data, position)
        symbols.append((string(strings, entry[0]), position, entry))
    return data, sections, names, symbols


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True)
    parser.add_argument('--linker', required=True)
    parser.add_argument('--work', default=os.environ.get('TEST_TMPDIR'))
    args = parser.parse_args()
    if not args.work:
        parser.error('--work is required outside Bazel')
    compiler, linker = (str(Path(p).resolve()) for p in (args.compiler, args.linker))
    work = Path(args.work).resolve() / 'lld-symbol-origin'
    work.mkdir(exist_ok=False, parents=True)
    commands, results = [], []

    def run(command):
        result = subprocess.run(command, cwd=work, capture_output=True, text=True)
        commands.append({'argv': command, 'exit': result.returncode,
                         'stdout': result.stdout, 'stderr': result.stderr})
        (work / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if result.returncode:
            raise RuntimeError(result.stderr)

    strong = ('.section .data.strong,"aw"\n.globl chosen\n.type chosen,@object\n'
              'chosen: .quad 2222\n.size chosen,8\n')
    weak = ('.section .data.weak,"aw"\n.weak weak_entry\n.type weak_entry,@object\n'
            'weak_entry: .long 1111\n.size weak_entry,4\n')
    # Self-contained v2 CTF with two unknown object associations, no types,
    # and its required empty string. The CTF section is valid, not a marker.
    ctf = struct.pack('<HBB8I', 0xcff1, 2, 0, 0, 0, 0, 0, 4, 4, 4, 1) + b'\0' * 5
    for strong_first in (True, False):
        for with_ctf in (False, True):
            stem = f'{"strong" if strong_first else "weak"}-first-{int(with_ctf)}'
            assembly = strong + weak if strong_first else weak + strong
            if with_ctf:
                assembly += '.section .SUNW_ctf,""\n.byte ' + ','.join(map(str, ctf)) + '\n'
            source = work / (stem + '.s')
            source.write_text(assembly)
            original = work / (stem + '.original.o')
            run([compiler, '-target', 'x86_64-unknown-freebsd', '-c', str(source), '-o', str(original)])
            data, _, _, symbols = read_elf(original)
            chosen = next(s for s in symbols if s[0] == 'chosen')
            losing = next(s for s in symbols if s[0] == 'weak_entry')
            assert (chosen[1] < losing[1]) == strong_first
            struct.pack_into('<I', data, losing[1], chosen[2][0])
            collision = work / (stem + '.o')
            collision.write_bytes(data)
            for mode in ('-r', '-shared'):
                output = work / (stem + ('.rel.o' if mode == '-r' else '.so'))
                run([linker, mode, str(collision), '-o', str(output)])
                data, sections, names, symbols = read_elf(output)
                selected = next(s[2] for s in symbols if s[0] == 'chosen')
                section = sections[selected[3]]
                location = section[4] + selected[4] - section[3]
                payload = struct.unpack_from('<Q', data, location)[0]
                assert selected[1] >> 4 == 1, 'strong global binding was lost'
                assert selected[5] == 8, 'strong size was lost'
                assert payload == 2222, 'selected section/value refers to losing weak definition'
                results.append({'strong_first': strong_first, 'with_ctf': with_ctf,
                                'mode': mode, 'section': names[selected[3]], 'size': selected[5],
                                'payload': payload, 'sha256': hashlib.sha256(data).hexdigest()})
    summary = {'passed': len(results), 'cases': results}
    (work / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
