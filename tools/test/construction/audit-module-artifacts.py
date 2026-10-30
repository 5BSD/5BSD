#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check a declared module/debug family without installing or loading it."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess


def elf(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('this qualification requires ELF64 little endian')
    header = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    if header[0:2] != (1, 62) or header[10] != 64 or not header[11]:
        raise ValueError('expected amd64 relocatable module')
    entries = [struct.unpack_from('<IIQQQQIIQQ', data, header[5] + i * header[10])
               for i in range(header[11])]
    def payload(entry):
        if entry[1] == 8:
            return b''
        offset, size = entry[4:6]
        if offset + size > len(data):
            raise ValueError('truncated section')
        return data[offset:offset + size]
    strings = payload(entries[header[12]])
    names = [strings[e[0]:strings.index(b'\0', e[0])].decode() for e in entries]
    sections = {n: (e, payload(e)) for n, e in zip(names, entries)}
    symbols = {}
    for entry in entries:
        if entry[1] != 2:
            continue
        if entry[9] != 24:
            raise ValueError('unexpected symbol size')
        strings = payload(entries[entry[6]])
        for offset in range(entry[4], entry[4] + entry[5], entry[9]):
            name, info, other, index, value, size = struct.unpack_from('<IBBHQQ', data, offset)
            name = strings[name:strings.index(b'\0', name)].decode()
            if name and index and info & 15 not in (3, 4):
                symbols[name] = (info >> 4, value, size)
    return sections, symbols


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kldxref', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    args.work.mkdir(mode=0o700)
    records = []
    complete = False
    digests = {}
    def check(name, condition):
        records.append({'case': name, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(name)
    def run(tool, *arguments):
        return subprocess.run([str(tool), *map(str, arguments)], check=True,
                              capture_output=True, text=True, timeout=30).stdout
    try:
        policy = json.loads((args.fixtures / 'module-policy.json').read_text())
        name = policy['name']
        runtime = args.fixtures / (name + '.ko')
        full = args.fixtures / (name + '.ko.full')
        debug = args.fixtures / (name + '.ko.debug')
        digests = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (runtime, full, debug)}
        rs, symbols = elf(runtime)
        fs, _ = elf(full)
        ds, _ = elf(debug)
        check('exports', {n for n, (binding, _, _) in symbols.items() if binding in (1, 2)} == set(policy['exports']))
        for section in ('.text', '.rodata'):
            check(section + '_page_boundary', rs[section][0][5] > 0 and rs[section][0][5] % policy['page_size'] == 0)
        def allocated(sections):
            return {n: (e[1], e[2], e[5], e[8], data) for n, (e, data) in sections.items() if e[2] & 2}
        check('split_preserves_allocated_sections', allocated(rs) == allocated(fs))
        check('debug_split', '.debug_info' not in rs and '.debug_line' not in rs and
              all(n in fs and n in ds for n in ('.debug_info', '.debug_line')))
        notes = [sections['.note.gnu.build-id'][1] for sections in (rs, fs, ds)]
        check('build_id_family', len(set(notes)) == 1 and struct.unpack_from('<III', notes[0]) == (4, 20, 3) and notes[0][12:16] == b'GNU\0')
        spec = importlib.util.spec_from_file_location('debug_check', args.fixtures / 'elf-debug-check.py')
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        checker.verify(runtime, debug, module=True)
        check('debug_link', True)
        corrupt = args.work / debug.name
        corrupt.write_bytes(debug.read_bytes() + b'corrupt')
        try:
            checker.verify(runtime, corrupt, module=True)
        except ValueError as error:
            check('corrupt_debug_rejected', 'CRC' in str(error))
        else:
            check('corrupt_debug_rejected', False)
        try:
            checker.verify(runtime, debug)
        except ValueError as error:
            check('userland_mode_rejects_module', 'static symbol' in str(error))
        else:
            check('userland_mode_rejects_module', False)
        check('sdt_symbols', all(name in symbols and symbols[name][0] == 0 for name in policy['sdt_symbols']))
        for section, expected in policy['linker_sets'].items():
            check(section, rs[section][0][5] == expected['bytes'])
            check(section + '_relocations', rs['.rela' + section][0][5] == expected['relocations'] * 24)
        ctf = run(args.fixtures / 'ctfdump', '-l', '-t', '-d', runtime)
        full_ctf = run(args.fixtures / 'ctfdump', '-l', '-t', '-d', full)
        # Strip-debug removes STT_FILE symbols and renumbers ELF indices.
        # Compare CTF bytes and symbol/type associations, not printed ELF indices.
        check('ctf_symbol_table_link', rs['.SUNW_ctf'][0][6] == list(rs).index('.symtab'))
        check('ctf_section_preserved', bool(rs['.SUNW_ctf'][1]) and rs['.SUNW_ctf'][1] == fs['.SUNW_ctf'][1])
        def data_objects(text):
            return [(int(index), int(type_id), name) for index, type_id, name in
                    re.findall(r'^\s*\[(\d+)\]\s+(\d+)\s+(\S+)\s+\(\d+\)$', text, re.M)]
        data = data_objects(ctf)
        check('ctf_symbol_associations_preserved', bool(data) and data == data_objects(full_ctf))
        types = {int(i): name for i, name in re.findall(r'^\s*<(\d+)> (.+)$', ctf, re.M)}
        for symbol, expected in policy['ctf_types'].items():
            descriptions = [types.get(type_id, '') for _, type_id, name in data if name == symbol]
            check('ctf_type_' + symbol, len(descriptions) == 1 and descriptions[0].startswith(expected + ' ('))
        (args.work / 'ctf.txt').write_text(ctf)
        version = re.search(r'^#define\s+__FreeBSD_version\s+(\d+)', (args.fixtures / 'param.h').read_text(), re.M)[1]
        seed = args.work / 'modules'
        seed.mkdir()
        shutil.copyfile(runtime, seed / runtime.name)
        description = run(args.kldxref, '-d', seed)
        check('kernel_tied_dependency', 'depends on kernel.' + version + ' (' + version + ',' + version + ')' in description)
        check('module_identity', '  module ' + name + '\n' in description and '  interface ' + name + '.' + str(policy['version']) + '\n' in description)
        (args.work / 'metadata.txt').write_text(description)
        run(args.kldxref, seed)
        hints = (seed / 'linker.hints').read_bytes()
        check('hints_created', len(hints) > 4 and hints[:4] == struct.pack('<I', 1))
        run(args.kldxref, seed)
        check('hints_repeat', hints == (seed / 'linker.hints').read_bytes())
        complete = True
    except Exception as error:
        records.append({'case': 'audit_exception', 'passed': False, 'error': str(error)})
        raise
    finally:
        (args.work / 'result.json').write_text(json.dumps({'checks': records,
            'passed': complete and all(r['passed'] for r in records), 'artifact_sha256': digests,
            'scope': 'static module/debug/CTF/metadata checks; no module loaded'}, indent=2) + '\n')


if __name__ == '__main__':
    main()
