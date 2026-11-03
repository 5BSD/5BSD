#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise SUNW CTF formats with an explicitly supplied amd64 fixture/tool.

The baseline must be localization-audit.py's baseline.o. Big-endian cases
exercise CTF serialization inside an amd64 ELF container, not a cross-built
kernel. Fixture type records are independently constructed named structures.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import zlib

spec = importlib.util.spec_from_file_location('localization', Path(__file__).with_name('localization-audit.py'))
localization = importlib.util.module_from_spec(spec)
spec.loader.exec_module(localization)


def sections(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('expected little-endian ELF64 fixture')
    h = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    if h[:2] != (1, 62) or h[10] != 64:
        raise ValueError('expected amd64 relocatable fixture')
    entries = [struct.unpack_from('<IIQQQQIIQQ', data, h[5] + i * 64) for i in range(h[11])]
    names = data[entries[h[12]][4]:sum(entries[h[12]][4:6])]
    result = {}
    for index, entry in enumerate(entries):
        name = names[entry[0]:names.index(b'\0', entry[0])].decode()
        if name in result:
            raise ValueError('duplicate section name')
        result[name] = (index, entry, data[entry[4]:entry[4] + entry[5]])
    return result


def make_ctf(table, version, endian, compressed):
    width = 2 if version == 2 else 4
    pack = lambda values: struct.pack(endian + ('H' if width == 2 else 'I') * len(values), *values)
    names = b'\0global_payload\0local_payload\0exported_payload\0'
    types = b''
    for name, size in [(b'global_payload', 4), (b'local_payload', 8), (b'exported_payload', 16)]:
        info = (6 << (11 if version == 2 else 26)) | (1 << (10 if version == 2 else 25))
        types += struct.pack(endian + ('IHH' if width == 2 else 'III'), names.index(name), info, size)
    objects, functions, records = b'', b'', {}
    for ordinal, (_, identity, binding) in enumerate(table):
        type_id = 3 if identity[0].startswith('exported_') else 1 if binding == 1 and identity[0] != 'call_static' else 2
        if identity[1] == 1:
            record = pack([type_id])
            objects += record
        else:
            count = ordinal % 3
            info = (5 << (11 if version == 2 else 26)) | count
            arguments = [type_id] * count
            if count == 2:
                arguments[-1] = 0  # Include a variadic function record.
            record = pack([info, type_id] + arguments)
            functions += record
        records[identity] = record
    labels = struct.pack(endian + "II", 1, 3)
    functions += bytes((-(len(labels) + len(objects) + len(functions))) % 4)
    body = labels + objects + functions + types + names
    header = struct.pack(endian + 'HBB8I', 0xcff1, version, int(compressed), 0, 0, 0,
                         len(labels), len(labels) + len(objects), len(labels) + len(objects) + len(functions),
                         len(labels) + len(objects) + len(functions) + len(types), len(names))
    return header + (zlib.compress(body) if compressed else body), records, types + names


def decode(path):
    sec = sections(path)
    data = sec['.SUNW_ctf'][2]
    endian = '<' if data[:2] == b'\xf1\xcf' else '>'
    magic, version, flags, _, _, _, obj, fun, typ, strings, length = struct.unpack_from(endian + 'HBB8I', data)
    if magic != 0xcff1 or version not in (2, 3):
        raise ValueError('invalid CTF header')
    body = zlib.decompress(data[36:]) if flags & 1 else data[36:]
    if len(body) != strings + length:
        raise ValueError('CTF payload size mismatch')
    width = 2 if version == 2 else 4
    positions = {1: obj, 2: fun}
    records = {}
    for _, identity, _ in localization.symbols(path):
        offset = positions[identity[1]]
        size = width
        if identity[1] == 2:
            info = int.from_bytes(body[offset:offset + width], 'little' if endian == '<' else 'big')
            if info:
                size = (2 + (info & (0x3ff if width == 2 else 0xffffff))) * width
        records[identity] = body[offset:offset + size]
        positions[identity[1]] += size
    return records, body[typ:], sec['.SUNW_ctf'][1][6] == sec['.symtab'][0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--objcopy', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--ctfdump', type=Path, required=True)
    parser.add_argument('--ldd', type=Path, required=True)
    parser.add_argument('--objcopy-library-directory', type=Path, action='append', default=[])
    parser.add_argument('--ctf-library-directory', type=Path, action='append', default=[])
    parser.add_argument('--semantic-reader', type=Path,
                        help='also check packed fixtures with this explicit ctf_semantics.py')
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=False)
    report = {'passed': False, 'checks': [], 'commands': [], 'inputs': {}}
    for name in ('objcopy', 'baseline', 'ctfdump'):
        path = getattr(args, name).resolve(strict=True)
        report['inputs'][name] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    semantic = None
    if args.semantic_reader:
        path = args.semantic_reader.resolve(strict=True)
        report['inputs']['semantic_reader'] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        module_spec = importlib.util.spec_from_file_location('selected_ctf_semantics', path)
        semantic = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(semantic)
    tool_env = dict(os.environ)
    tool_env.pop('LD_LIBRARY_PATH', None)
    if args.objcopy_library_directory:
        tool_env['LD_LIBRARY_PATH'] = ':'.join(map(str, args.objcopy_library_directory))
    report['objcopy_environment'] = {'LD_LIBRARY_PATH': tool_env.get('LD_LIBRARY_PATH', '')}
    trace = subprocess.run([str(args.ldd), str(args.objcopy)], env=tool_env,
                           capture_output=True, text=True, timeout=30)
    if trace.returncode and 'not a dynamic ELF executable' not in trace.stdout + trace.stderr:
        raise ValueError('objcopy dependency inspection failed: ' + trace.stderr)
    report['objcopy_dependencies'] = {'ldd': trace.stdout, 'stderr': trace.stderr, 'status': trace.returncode, 'sha256': {}}
    for line in trace.stdout.splitlines():
        if '=> not found' in line:
            raise ValueError('unresolved objcopy dependency')
        if '=> /' in line:
            path = Path(line.split('=> ', 1)[1].split()[0]).resolve(strict=True)
            report['objcopy_dependencies']['sha256'][str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    table = localization.symbols(args.baseline)
    def run(*arguments):
        command = list(map(str, (args.objcopy, *arguments)))
        report['commands'].append(command)
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=30, env=tool_env)
    def check(case, passed):
        report['checks'].append({'case': case, 'passed': bool(passed)})
        if not passed:
            raise AssertionError(case)
    try:
        for version in (2, 3):
            for endian in ('<', '>'):
                for compressed in (False, True):
                    tag = f'v{version}-' + ('le' if endian == '<' else 'be') + ('-z' if compressed else '-raw')
                    payload, expected, tail = make_ctf(table, version, endian, compressed)
                    ctf = args.work / (tag + '.ctf'); ctf.write_bytes(payload)
                    baseline = args.work / (tag + '-baseline.o')
                    run('--update-section=.SUNW_ctf=' + str(ctf), args.baseline, baseline)
                    if endian == '<':
                        env = dict(os.environ)
                        if args.ctf_library_directory:
                            env['LD_LIBRARY_PATH'] = ':'.join(map(str, args.ctf_library_directory))
                        dump = subprocess.run([str(args.ctfdump), '-t', '-d', '-f', str(baseline)],
                                              env=env, check=True, capture_output=True, text=True, timeout=30).stdout
                        baseline.with_suffix('.ctf.txt').write_text(dump)
                        descriptions = localization.associations(baseline, dump)
                        wanted = {identity: 'STRUCT ' + ('exported_payload' if identity[0].startswith('exported_') else
                                  'global_payload' if binding == 1 and identity[0] != 'call_static' else 'local_payload')
                                  for _, identity, binding in table}
                        check(tag + '-independent-ctfdump', descriptions == wanted)
                    if semantic:
                        graph = semantic.Graph(payload, [identity for _, identity, _ in table])
                        check(tag + '-semantic-baseline', len(graph.symbols) == len(table))
                    for name, flags in [('copy', []), ('localize', ['-Lshared_data', '-Lshared_function']),
                                        ('debug-strip', ['--strip-debug']), ('remove', ['--strip-symbol=exported_function']),
                                        ('rename', ['--redefine-sym=shared_data=renamed_data', '--redefine-sym=shared_function=renamed_function']),
                                        ('add-object', ['--add-symbol=added=.data:0,global,object']),
                                        ('add-function', ['--add-symbol=added=.text:0,global,function'])]:
                        output = args.work / (tag + '-' + name + '.o')
                        run(*flags, baseline, output)
                        actual, actual_tail, linked = decode(output)
                        wanted = {identity: value for identity, value in expected.items()
                                  if not (name == 'remove' and identity[0] == 'exported_function')}
                        if name == 'rename':
                            wanted = {(('renamed_' + identity[0][7:], *identity[1:]) if identity[0].startswith('shared_') else identity): value
                                      for identity, value in wanted.items()}
                        if name.startswith('add-'):
                            wanted[('added', 1 if name == 'add-object' else 2, '.data' if name == 'add-object' else '.text', 0, 0)] = bytes(2 if version == 2 else 4)
                        if semantic:
                            graph = semantic.Graph(sections(output)['.SUNW_ctf'][2],
                                                   [identity for _, identity, _ in localization.symbols(output)])
                            check(tag + '-' + name + '-semantic', len(graph.symbols) == len(wanted))
                        section = sections(output)['.SUNW_ctf'][2]
                        output_body = zlib.decompress(section[36:]) if compressed else section[36:]
                        check(tag + '-' + name, actual == wanted and actual_tail == tail and linked and
                              output_body[:8] == struct.pack(endian + 'II', 1, 3))
                    # Equal zero bytes can change from object to function
                    # associations. Their header boundaries must change too.
                    temporary = args.work / (tag + '-boundary-added.o')
                    run('--add-symbol=temporary=.data:0,global,object', baseline, temporary)
                    unknown_table = localization.symbols(temporary)
                    width = 2 if version == 2 else 4
                    objects = sum(identity[1] == 1 for _, identity, _ in unknown_table)
                    functions = len(unknown_table) - objects
                    fun = objects * width
                    typ = (fun + functions * width + 3) & ~3
                    body = bytes(typ) + b'\0'
                    header = struct.pack(endian + 'HBB8I', 0xcff1, version, int(compressed),
                                         0, 0, 0, 0, fun, typ, typ, 1)
                    raw = args.work / (tag + '-boundary.ctf')
                    raw.write_bytes(header + (zlib.compress(body) if compressed else body))
                    unknown = args.work / (tag + '-boundary-input.o')
                    run('--update-section=.SUNW_ctf=' + str(raw), temporary, unknown)
                    output = args.work / (tag + '-boundary-output.o')
                    run('--strip-symbol=temporary', '--add-symbol=added=.text:0,global,function', unknown, output)
                    actual, tail, linked = decode(output)
                    payload = sections(output)['.SUNW_ctf'][2]
                    actual_fun = struct.unpack_from(endian + 'I', payload, 20)[0]
                    check(tag + '-equal-bytes-changed-boundary', actual_fun == fun - width and linked and
                          tail == b'\0' and len(actual) == len(unknown_table) and
                          all(record == bytes(width) for record in actual.values()))
        # An unrelated OwnedDataSection must not acquire a .symtab link.
        payload = args.work / 'ordinary-data'; payload.write_bytes(b'ordinary section\0')
        output = args.work / 'ordinary.o'
        run('--add-section=.ctf_test=' + str(payload), args.baseline, output)
        check('ordinary-section-link', sections(output)['.ctf_test'][1][6] == 0)
        # Opaque/unsupported CTF can be copied or removed when no association
        # rewrite is needed. Changing symbol order must reject it explicitly.
        payload = bytearray(sections(args.baseline)['.SUNW_ctf'][2])
        payload[2] = 127
        raw = args.work / 'unknown.ctf'; raw.write_bytes(payload)
        unknown = args.work / 'unknown.o'
        run('--update-section=.SUNW_ctf=' + str(raw), args.baseline, unknown)
        for name, flags in [('copy', []), ('debug', ['--strip-debug']), ('remove', ['--remove-section=.SUNW_ctf'])]:
            out = args.work / ('unknown-' + name + '.o')
            run(*flags, unknown, out)
            sec = sections(out)
            check('unknown-' + name, '.SUNW_ctf' not in sec if name == 'remove' else sec['.SUNW_ctf'][2] == payload)
        out = args.work / 'unknown-reorder.o'
        failure = subprocess.run([str(args.objcopy), '-Lshared_data', str(unknown), str(out)],
                                 env=tool_env, capture_output=True, text=True, timeout=30)
        check('unknown-reorder-rejected', failure.returncode > 0 and not out.exists() and 'unsupported version' in failure.stderr)
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        (args.work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
