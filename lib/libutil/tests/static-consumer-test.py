#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise static extraction without invoking credential-changing functions."""
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import unittest


def defined_symbols(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01' or len(data) < 64:
        raise ValueError('bounded ELF64 little endian required')
    if struct.unpack_from('<HH', data, 16) != (2, 62):
        raise ValueError('static amd64 executable required')
    offset = struct.unpack_from('<Q', data, 40)[0]
    stride, count = struct.unpack_from('<HH', data, 58)
    if stride != 64 or not count or offset + count * stride > len(data):
        raise ValueError('section table bounds')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset + n * stride)
                for n in range(count)]
    def contents(section):
        start, size = section[4:6]
        if start + size > len(data):
            raise ValueError('section bounds')
        return data[start:start + size]
    result = set()
    for section in sections:
        if section[1] != 2:
            continue
        if section[6] >= count or section[9] != 24 or section[5] % 24:
            raise ValueError('symbol table bounds')
        strings = contents(sections[section[6]])
        table = contents(section)
        for pos in range(0, len(table), 24):
            name, info, other, index, value, size = struct.unpack_from('<IBBHQQ', table, pos)
            end = strings.find(b'\0', name)
            if end < 0:
                raise ValueError('symbol string bounds')
            if index:
                result.add(strings[name:end].decode('ascii'))
    if not result:
        raise ValueError('defined symbol table required')
    return result


def inspect_number(path, inventory):
    symbols = defined_symbols(path)
    if 'expand_number' not in symbols or 'setusercontext' in symbols:
        raise ValueError('unrelated credential object extraction')
    if '__bsd_dof_anchor_logincap_provider' in symbols:
        raise ValueError('unrelated logincap provider extraction')
    try:
        inventory(path)
    except ValueError as error:
        if str(error) != 'no emitted probe metadata':
            raise
    else:
        raise ValueError('unexpected number-only provider metadata')


def inspect_context(path, inventory):
    symbols = defined_symbols(path)
    if not {'setusercontext', '__bsd_dof_anchor_logincap_provider'} <= symbols:
        raise ValueError('selected credential object/provider required')
    value = inventory(path)
    schemas = [v for v in value['probe_schemas'] if v['provider'] == 'logincap']
    if len(schemas) != 1:
        raise ValueError('one selected logincap schema required')
    schema = schemas[0]
    expected = dict(function='setusercontext', name='setusercontext',
                    native_arguments=['char *', 'int', 'int', 'int'],
                    translated_arguments=['char *', 'int', 'int', 'int'],
                    argument_mapping=[0, 1, 2, 3], site_count=1, enabled_site_count=0)
    if any(schema.get(k) != v for k, v in expected.items()):
        raise ValueError('original logincap probe schema required')


class StaticConsumer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
        cls.number = root / 'lib/libutil/tests/static_number'
        cls.context = root / 'lib/libutil/tests/static_context_reference'
        path = root / 'tools/build/bazel/dtrace-dof-inventory.py'
        spec = importlib.util.spec_from_file_location('maintained_dof', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.inventory = staticmethod(module.inventory)

    def test_unrelated_extraction(self):
        inspect_number(self.number, self.inventory)

    def test_selected_provider(self):
        inspect_context(self.context, self.inventory)

    def run_safe(self, path):
        # drti reads this before main; neither fixture calls setusercontext.
        environment = dict(os.environ, DTRACE_DOF_INIT_DISABLE='1')
        result = subprocess.run([str(path)], env=environment, capture_output=True,
                                timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'')

    def test_number_runtime(self):
        self.run_safe(self.number)

    def test_address_only_runtime(self):
        self.run_safe(self.context)


if __name__ == '__main__':
    unittest.main(verbosity=2)
