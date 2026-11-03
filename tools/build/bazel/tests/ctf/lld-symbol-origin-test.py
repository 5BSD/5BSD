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
import resource
from pathlib import Path
import struct
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_elf(path, machine=62):
    data = bytearray(path.read_bytes())
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != machine:
        raise ValueError('fixture requires little-endian ELF64 of the requested machine')
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
    parser.add_argument('--compiler-runtime', nargs='+', default=[],
                        help='Declared shared-library inputs for the fixture compiler only')
    parser.add_argument('--linker', required=True)
    parser.add_argument('--work', default=os.environ.get('TEST_TMPDIR'))
    args = parser.parse_args()
    if not args.work:
        parser.error('--work is required outside Bazel')
    compiler, linker = (str(Path(p).resolve()) for p in (args.compiler, args.linker))
    work = Path(args.work).resolve() / 'lld-symbol-origin'
    work.mkdir(exist_ok=False, parents=True)
    commands, results = [], []
    # The Python interpreter's SDK libraries must not override source-built
    # tools' RUNPATHs. Select each child tool's own declared runtime instead.
    child_environment = dict(os.environ)
    for name in ('LD_LIBRARY_PATH', 'LD_PRELOAD'):
        child_environment.pop(name, None)
    compiler_environment = dict(child_environment)
    compiler_runtime = [Path(p).resolve(strict=True) for p in args.compiler_runtime]
    if compiler_runtime:
        compiler_environment['LD_LIBRARY_PATH'] = ':'.join(
            sorted({str(p.parent) for p in compiler_runtime}))

    def run(command, success=True, max_file_size=None):
        def bound():
            resource.setrlimit(resource.RLIMIT_FSIZE, (max_file_size, max_file_size))
        environment = compiler_environment if command[0] == compiler else child_environment
        result = subprocess.run(command, cwd=work, capture_output=True, text=True,
                                env=environment, preexec_fn=bound if max_file_size else None)
        commands.append({'argv': command, 'exit': result.returncode,
                         'library_path': environment.get('LD_LIBRARY_PATH'),
                         'stdout': result.stdout, 'stderr': result.stderr})
        (work / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if (result.returncode == 0) != success:
            raise RuntimeError(result.stderr)
        return result

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
    # The linker adds an actual AArch64 long-branch thunk during layout. Its
    # new local function needs an unknown CTF association before final sorting.
    # Separate explicit segments keep the large virtual branch distance from
    # becoming a large file. Bound the child file size as a regression guard.
    thunk_ctf = struct.pack('<HBB8I', 0xcff1, 3, 0, 0, 0, 0, 0, 0, 8, 8, 1) + bytes(9)
    source = work / 'thunk.s'
    source.write_text('.section .text.start,"ax"\n.globl start\n.type start,%function\n'
        'start: b far\n.size start,.-start\n.section .text.far,"ax"\n'
        '.globl far\n.type far,%function\nfar: ret\n.size far,.-far\n'
        '.section .SUNW_ctf,""\n.byte ' + ','.join(map(str, thunk_ctf)) + '\n')
    layout = work / 'thunk.ld'
    layout.write_text('PHDRS { first PT_LOAD FLAGS(5); second PT_LOAD FLAGS(5); }\n'
        'SECTIONS { .text.start 0x10000 : { *(.text.start) } :first\n'
        '.text.far 0x90000000 : { *(.text.far) } :second\n'
        '.SUNW_ctf 0 : { *(.SUNW_ctf) } :NONE }\n')
    obj, output = work / 'thunk.o', work / 'thunk.so'
    run([compiler, '-target', 'aarch64-unknown-freebsd', '-c', str(source), '-o', str(obj)])
    run([linker, '-shared', '--no-relax', '-T', str(layout), '-o', str(output), str(obj)],
        max_file_size=16 * 1024 * 1024)
    data, sections, names, symbols = read_elf(output, machine=183)
    functions = [entry for name, pos, entry in symbols
                 if name and entry[1] & 15 == 2 and entry[3]]
    assert len(functions) > 2, 'linker did not add a function thunk'
    assert any('Thunk' in name for name, pos, entry in symbols)
    section = sections[names.index('.SUNW_ctf')]
    assert section[6] == names.index('.symtab')
    payload = data[section[4]:section[4] + section[5]]
    header = struct.unpack_from('<HBB8I', payload)
    assert header[:3] == (0xcff1, 3, 0)
    assert header[6:10] == (0, 0, 4 * len(functions), 4 * len(functions))
    assert payload[36:] == bytes(4 * len(functions) + 1)
    assert output.stat().st_size < 1024 * 1024
    results.append({'case': 'aarch64-layout-thunk', 'functions': len(functions),
                    'output_bytes': output.stat().st_size})

    # CTF dictionaries are metadata, not addressable program data. Do not
    # silently translate a relocation into a dictionary whose offsets changed.
    source = work / 'dictionary-reference.s'
    reference_ctf = struct.pack('<HBB8I', 0xcff1, 3, 0, 0, 0, 0, 0, 4, 4, 4, 1) + bytes(5)
    source.write_text('.data\n.globl pointer\n.type pointer,@object\n'
        'pointer: .quad ctf_header\n.size pointer,8\n.section .SUNW_ctf,""\n'
        '.globl ctf_header\nctf_header:\n.byte ' + ','.join(map(str, reference_ctf)) + '\n')
    obj = work / 'dictionary-reference.o'
    run([compiler, '-target', 'x86_64-unknown-freebsd', '-c', str(source), '-o', str(obj)])
    rejected = run([linker, '-r', '-o', str(work / 'rejected.o'), str(obj)], success=False)
    assert 'relocations into a CTF dictionary are unsupported' in rejected.stderr
    results.append({'case': 'reject-relocation-into-dictionary'})

    summary = {'passed': len(results), 'cases': results,
               'compiler_runtime_sha256': {str(p): digest(p) for p in compiler_runtime}}
    (work / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    if os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR'):
        destination = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR'])
        (destination / 'lld-symbol-origins.json').write_text(json.dumps(summary, indent=2) + '\n')
        (destination / 'lld-symbol-commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
