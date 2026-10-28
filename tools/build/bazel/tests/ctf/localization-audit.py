#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Reproduce CTF symbol localization errors with explicitly selected tools.

This diagnostic builds no installed software. A failure remains a failure:
neither known corruption nor a successful command is treated as qualification.
The ELF reader deliberately accepts only the amd64 fixture format.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess


def symbols(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('expected ELF64 little endian')
    h = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    if h[:2] != (1, 62) or h[10] != 64:
        raise ValueError('expected amd64 relocatable ELF')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, h[5] + i * 64)
                for i in range(h[11])]
    def payload(section):
        start, size = section[4:6]
        if start + size > len(data):
            raise ValueError('truncated ELF')
        return data[start:start + size]
    def string(table, offset):
        return table[offset:table.index(b'\0', offset)].decode()
    names = payload(sections[h[12]])
    result = []
    for section in sections:
        if section[1] != 2:
            continue
        if section[9] != 24:
            raise ValueError('invalid symbol entry size')
        strings = payload(sections[section[6]])
        for index, offset in enumerate(range(0, section[5], 24)):
            name, info, _, shndx, value, size = struct.unpack_from('<IBBHQQ', payload(section), offset)
            kind = info & 15
            if kind not in (1, 2) or shndx == 0:
                continue
            if shndx >= len(sections):
                raise ValueError('fixture requires ordinary defined symbols')
            identity = (string(strings, name), kind, string(names, sections[shndx][0]), value, size)
            result.append((index, identity, info >> 4))
    if len({identity for _, identity, _ in result}) != len(result):
        raise ValueError('ambiguous fixture identity')
    return result


def associations(path, dump):
    table = symbols(path)
    types = {int(i): description for i, description in
             re.findall(r'^\s*<(\d+)> (.+)$', dump, re.M)}
    objects = {int(index): int(type_id) for _, type_id, index in re.findall(
        r'^\s*\[(\d+)\]\s+(\d+)\s+\S+\s+\((\d+)\)$', dump, re.M)}
    functions = {int(index): (name, int(type_id)) for index, name, type_id in re.findall(
        r'^\s*\[(\d+)\] FUNC \(([^)]+)\) returns: (\d+) args:', dump, re.M)}
    result = {}
    ordinal = 0
    for index, identity, _ in table:
        if identity[1] == 1:
            type_id = objects.get(index, 0)
        else:
            name, type_id = functions.get(ordinal, ('', 0))
            if name != identity[0]:
                raise ValueError('function table does not match ELF order')
            ordinal += 1
        description = types.get(type_id, 'UNKNOWN')
        # Fixture types are named structures, independent of type-ID allocation.
        result[identity] = description.split(' (', 1)[0]
    if len(objects) != sum(identity[1] == 1 for _, identity, _ in table) or len(functions) != ordinal:
        raise ValueError('CTF entry count does not match fixture symbols')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for tool in ('cc', 'ld', 'objcopy', 'ctfconvert', 'ctfmerge', 'ctfdump'):
        parser.add_argument('--' + tool, type=Path, required=True)
    parser.add_argument('--ctf-library-directory', type=Path, action='append', default=[])
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=False)
    report = {'passed': False, 'scope': 'amd64 synthetic CTF localization; no kernel loading',
              'checks': [], 'commands': [], 'tools': {}, 'sources': {}}
    env = dict(os.environ, LC_ALL='C')
    ctfenv = dict(env)
    if args.ctf_library_directory:
        ctfenv['LD_LIBRARY_PATH'] = ':'.join(map(str, args.ctf_library_directory))
    def run(tool, *arguments, ctf=False):
        command = list(map(str, (tool, *arguments)))
        report['commands'].append(command)
        return subprocess.run(command, check=True, capture_output=True, text=True,
                              env=ctfenv if ctf else env, timeout=60).stdout
    def dump(path):
        text = run(args.ctfdump, '-t', '-d', '-f', path, ctf=True)
        path.with_suffix(path.suffix + '.ctf.txt').write_text(text)
        return associations(path, text)
    try:
        for tool in ('cc', 'ld', 'objcopy', 'ctfconvert', 'ctfmerge', 'ctfdump'):
            path = getattr(args, tool).resolve(strict=True)
            setattr(args, tool, path)
            report['tools'][tool] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        objects = []
        for suffix in ('global', 'static'):
            source = Path(__file__).with_name('localization-' + suffix + '.c')
            report['sources'][source.name] = hashlib.sha256(source.read_bytes()).hexdigest()
            obj = args.work / (suffix + '.o')
            run(args.cc, '-O0', '-g', '-gdwarf-4', '-fno-pic', '-c', source, '-o', obj)
            run(args.ctfconvert, '-g', '-l', 'localization-audit', obj, ctf=True)
            objects.append(obj)
        linked = args.work / 'linked.o'
        run(args.ld, '-r', '-o', linked, *objects)
        baseline = args.work / 'baseline.o'
        shutil.copyfile(linked, baseline)
        run(args.ctfmerge, '-g', '-l', 'localization-audit', '-o', baseline, *objects, ctf=True)
        expected = {identity: 'STRUCT ' + ('exported_payload' if identity[0].startswith('exported_') else
                         'global_payload' if binding == 1 and identity[0] != 'call_static' else 'local_payload')
                    for _, identity, binding in symbols(baseline)}
        actual = dump(baseline)
        if actual != expected:
            raise AssertionError('baseline CTF must match fixture source types')
        report['checks'].append({'case': 'baseline', 'passed': True})
        for mode in ('merge-then-localize', 'localize-then-fuzzy-merge'):
            output = args.work / (mode + '.o')
            run(args.objcopy, '-Lshared_data', '-Lshared_function',
                baseline if mode == 'merge-then-localize' else linked, output)
            if mode == 'localize-then-fuzzy-merge':
                run(args.ctfmerge, '-g', '-f', '-l', 'localization-audit', '-o', output, *objects, ctf=True)
            actual = dump(output)
            report['checks'].append({'case': mode, 'passed': actual == expected,
                'associations': [{'identity': identity, 'expected': description, 'actual': actual.get(identity)}
                                 for identity, description in expected.items()]})
        report['passed'] = all(check['passed'] for check in report['checks'])
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        (args.work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
