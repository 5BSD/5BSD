#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Reject cross-module imports whose supplied provider definitions are local.

This is a known-provider regression check, not complete kernel/module dependency
closure: imports with no definition in the supplied modules remain reported.
"""
import argparse
import json
import os
from pathlib import Path
import struct


def symbols(path):
    data = path.read_bytes()
    if len(data) < 64 or data[:5] != b'\x7fELF\x02' or data[5] not in (1, 2):
        raise ValueError('ELF64 module required: ' + str(path))
    order = '<' if data[5] == 1 else '>'
    header = struct.unpack_from(order + 'HHIQQQIHHHHHH', data, 16)
    if header[0] not in (1, 3) or header[10] != 64 or not header[11]:
        raise ValueError('ordinary module section table required')
    if header[5] + header[11] * 64 > len(data):
        raise ValueError('truncated module section table')
    sections = [struct.unpack_from(order + 'IIQQQQIIQQ', data, header[5] + n * 64)
                for n in range(header[11])]

    def payload(entry):
        if entry[4] + entry[5] > len(data):
            raise ValueError('truncated module section')
        return data[entry[4]:entry[4] + entry[5]]

    exports, local, required = set(), set(), set()
    tables = 0
    for entry in sections:
        if entry[1] != 2:
            continue
        tables += 1
        if entry[9] != 24 or entry[5] % 24 or entry[6] >= len(sections):
            raise ValueError('invalid ordinary symbol table')
        strings = sections[entry[6]]
        if strings[1] != 3:
            raise ValueError('symbol table must link to a string table')
        names = payload(strings)
        table = payload(entry)
        for at in range(0, entry[5], 24):
            offset, info, other, section, value, size = struct.unpack_from(
                order + 'IBBHQQ', table, at)
            if offset >= len(names) or section == 0xffff:
                raise ValueError('invalid symbol name or unsupported extended section')
            end = names.find(b'\0', offset)
            if end < 0:
                raise ValueError('unterminated symbol name')
            name = names[offset:end].decode('utf-8')
            if not name or (info & 15) in (3, 4):
                continue
            binding = info >> 4
            if section == 0:
                if binding == 1:
                    required.add(name)
            elif binding in (1, 2):
                exports.add(name)
            elif binding == 0:
                local.add(name)
    if tables != 1:
        raise ValueError('exactly one ordinary symbol table required')
    return dict(exports=exports, local=local, required=required)


def inspect(modules):
    exported = set().union(*(m['exports'] for m in modules.values()))
    findings, edges, unresolved = [], [], {}
    for consumer, module in modules.items():
        unresolved[consumer] = sorted(module['required'] - exported)
        for provider, other in modules.items():
            if provider == consumer:
                continue
            edges.extend(dict(consumer=consumer, provider=provider, symbol=name)
                         for name in sorted(module['required'] & other['exports']))
            findings.extend(dict(consumer=consumer, provider=provider, symbol=name)
                            for name in sorted((module['required'] - exported) & other['local']))
    return dict(localized_providers=findings, resolved_cross_module_references=edges,
                imports_without_supplied_global_provider=unresolved,
                scope='Known supplied provider bindings only; external/kernel providers and runtime loading remain unqualified.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module', action='append', required=True, help='name=ELF path')
    parser.add_argument('--expect-localized', action='store_true', help='Negative fixture must expose the localized-provider defect')
    args = parser.parse_args()
    modules = {}
    for value in args.module:
        name, separator, filename = value.partition('=')
        if not separator or not name or name in modules:
            raise ValueError('unique named module paths required')
        modules[name] = symbols(Path(filename))
    if len(modules) < 2:
        raise ValueError('at least two modules required')
    result = inspect(modules)
    if args.expect_localized:
        if not result['localized_providers']:
            raise ValueError('negative fixture did not reproduce hidden provider definitions')
    elif result['localized_providers']:
        raise ValueError('required provider symbols were localized: ' + json.dumps(result['localized_providers']))
    elif not result['resolved_cross_module_references']:
        raise ValueError('no cross-module provider references exercised')
    result['status'] = 'passed'
    result['negative_fixture'] = args.expect_localized
    if os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR'):
        (Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']) / 'provider-review.json').write_text(
            json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
