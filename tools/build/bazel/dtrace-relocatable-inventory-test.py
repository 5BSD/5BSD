#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Independent ELF64/DOF fixtures for metadata and actual symbol/site bindings."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('dof_inventory',
    Path(__file__).with_name('dtrace-dof-inventory.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def fixture(*, defined=True, alias='$dtrace123.fn', machine=62, kind=24,
            symbol_index=1, site=0, enabled_site=11, bad_patch=False, user_kind=2,
            function_value=0, address=0, extra_relocation=False, linked=False,
            binding=1, visibility=2):
    """One provider/probe, one ordinary site and one enabled site.

    The .text body has NOPs at 0..4 and XOR/NOPs at 8..12. DOF references
    its function through an R_X86_64_PC64 ELF relocation plus the matching
    DOF_RELO_DOFREL record. No compiler or external tool creates this fixture.
    """
    strings = b'\0p\0fn\0event\0int\0'
    probe = struct.pack('<Q6IBBHIHHI', address, 3, 6, 12, 12, 0, 0,
                        1, 1, 1, 0, 1, 0, 0)
    payloads = [strings, probe, b'\0', struct.pack('<I', site),
                struct.pack('<I', enabled_site),
                struct.pack('<11I', 0, 1, 2, 3, 1, 0, 0, 0, 0, 0, 4),
                struct.pack('<3I', 0, 7, 1), struct.pack('<2I2Q', 3, user_kind, 0, 0)]
    kinds = [8, 16, 17, 18, 26, 15, 12, 10]
    strides = [1, 48, 1, 4, 4, 44, 12, 24]
    body = bytearray(64 + 32 * len(payloads))
    descriptors = []
    for kind_dof, stride, payload in zip(kinds, strides, payloads):
        body.extend(b'\0' * (-len(body) % 8))
        descriptors.append((kind_dof, 8, 1, stride, len(body), len(payload)))
        body.extend(payload)
    ident = b'\x7fDOF\x02\x01\x02' + b'\0' * 9
    body[:64] = ident + struct.pack('<4I4Q', 0, 64, 32, 8, 64,
                                    len(body), len(body), 0)
    for index, descriptor in enumerate(descriptors):
        struct.pack_into('<4I2Q', body, 64 + index * 32, *descriptor)
    names = b'\0.shstrtab\0.strtab\0.symtab\0.text\0.SUNW_dof\0.rela.SUNW_dof\0'
    name_offsets = {name: names.index(name.encode() + b'\0') for name in
                    ['.shstrtab', '.strtab', '.symtab', '.text', '.SUNW_dof', '.rela.SUNW_dof']}
    symbols = b'\0' + alias.encode() + b'\0'
    symbol_table = b'\0' * 24 + struct.pack('<IBBHQQ', 1, (binding << 4) | 2, visibility,
                                          4 if defined else 0, function_value, 16)
    code = bytearray(b'\x90' * 8 + b'\x48\x33\xc0\x90\x90' + b'\x90' * 3)
    if bad_patch:
        code[0] = 0xcc
    relocation = struct.pack('<QQq', descriptors[1][4], (symbol_index << 32) | kind, 0)
    if extra_relocation:
        relocation += struct.pack('<QQq', descriptors[1][4] + 8, (1 << 32) | 24, 0)
    data = bytearray(64)
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for name, typ, flags, payload, link, info, stride in [
            ('.shstrtab', 3, 0, names, 0, 0, 0),
            ('.strtab', 3, 0, symbols, 0, 0, 0),
            ('.symtab', 2, 0, symbol_table, 2, 1, 24),
            ('.text', 1, 6, code, 0, 0, 0),
            ('.SUNW_dof', 0x6ffffff4, 2, body, 0, 0, 0),
            ('.rela.SUNW_dof', 4, 0, relocation, 3, 5, 24)]:
        data.extend(b'\0' * (-len(data) % 8))
        sections.append((name_offsets[name], typ, flags, 0, len(data), len(payload),
                         link, info, 8, stride))
        data.extend(payload)
    data.extend(b'\0' * (-len(data) % 8))
    shoff = len(data)
    for section in sections:
        data.extend(struct.pack('<IIQQQQIIQQ', *section))
    ident = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    data[:64] = ident + struct.pack('<HHIQQQIHHHHHH', 3 if linked else 1,
        machine, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(sections), 1)
    return data


class RelocatableInventoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def object(self, name='provider.o', **kwargs):
        path = self.root / name
        path.write_bytes(fixture(**kwargs))
        return path

    def rejected(self, message, **kwargs):
        with self.assertRaisesRegex(ValueError, message):
            checker.inventory(self.object(**kwargs), relocatable=True)

    def test_default_rejects_relocatable_input(self):
        with self.assertRaisesRegex(ValueError, 'linked executable or shared ELF'):
            checker.inventory(self.object())

    def test_explicit_metadata_resolves_actual_symbol_and_both_sites(self):
        result = checker.inventory(self.object(), relocatable=True)
        self.assertEqual(result['providers'], [{'name': 'p', 'attributes': [0] * 5}])
        probe = result['probe_locations'][0]
        self.assertEqual((probe['provider'], probe['function'], probe['name']), ('p', 'fn', 'event'))
        self.assertEqual((probe['offsets'], probe['enabled_offsets']), ([0], [11]))
        binding = result['relocatable_metadata']['bindings'][0]
        self.assertEqual(binding['symbol']['name'], '$dtrace123.fn')
        self.assertEqual((binding['code_section'], binding['symbol']['size']), ('.text', 16))
        self.assertEqual((binding['elf_relocation_kind'], binding['user_relocation_kind']), (24, 2))

    def test_hidden_weak_alias_resolves_actual_symbol_and_sites(self):
        result = checker.inventory(self.object(alias='$dtrace.fn', binding=2),
                                   relocatable=True)
        symbol = result['relocatable_metadata']['bindings'][0]['symbol']
        self.assertEqual((symbol['name'], symbol['binding'], symbol['visibility']),
                         ('$dtrace.fn', 2, 2))

    def test_alias_naming_requires_corresponding_binding(self):
        self.rejected('matching binding', alias='$dtrace.fn', binding=1)
        self.rejected('matching binding', binding=2)

    def test_weak_alias_must_be_hidden_and_have_valid_code(self):
        self.rejected('bounded hidden FUNC', alias='$dtrace.fn', binding=2,
                      visibility=0)
        self.rejected('bounded NOP/RET', alias='$dtrace.fn', binding=2,
                      bad_patch=True)

    def test_absolute_elf_and_user_relocation_pair_is_resolved(self):
        result = checker.inventory(self.object(kind=1, user_kind=1), relocatable=True)
        binding = result['relocatable_metadata']['bindings'][0]
        self.assertEqual((binding['elf_relocation_kind'], binding['user_relocation_kind']), (1, 1))

    def test_undefined_alias_requires_companion(self):
        self.rejected('one defined matching object symbol', defined=False)

    def test_actual_matching_companion_resolves_undefined_alias(self):
        result = checker.inventory(self.object(defined=False), relocatable=True,
                                   symbols=self.object('code.o'))
        self.assertEqual(len(result['relocatable_metadata']['bindings']), 1)

    def test_multiple_real_companions_resolve_exact_alias(self):
        code = self.object('code.o')
        other = self.object('other.o', alias='$dtrace124.fn')
        result = checker.inventory(self.object(defined=False), relocatable=True,
                                   symbols=[other, code])
        metadata = result['relocatable_metadata']
        self.assertEqual(len(metadata['symbol_objects']), 2)
        self.assertNotIn('symbols', metadata)
        self.assertEqual(metadata['bindings'][0]['symbol_source_sha256'],
                         checker.RelocatableDof.read(code)['sha256'])

    def test_ambiguous_companion_alias_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'one defined matching object symbol'):
            checker.inventory(self.object(defined=False), relocatable=True,
                              symbols=[self.object('left.o'), self.object('right.o')])

    def test_duplicate_companion_path_is_rejected(self):
        code = self.object('code.o')
        with self.assertRaisesRegex(ValueError, 'duplicate symbol object path'):
            checker.inventory(self.object(defined=False), relocatable=True,
                              symbols=[code, code])

    def test_empty_companion_selection_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'nonempty explicit symbol object paths'):
            checker.inventory(self.object(defined=False), relocatable=True, symbols=[])

    def test_multiple_companions_do_not_hide_bad_actual_code(self):
        with self.assertRaisesRegex(ValueError, 'bounded NOP/RET'):
            checker.inventory(self.object(defined=False), relocatable=True,
                              symbols=[self.object('bad.o', bad_patch=True),
                                       self.object('other.o', alias='$dtrace124.fn')])

    def test_cli_accepts_explicit_companion_objects(self):
        provider = self.object(defined=False)
        code = self.object('code.o')
        other = self.object('other.o', alias='$dtrace124.fn')
        output = self.root / 'result.json'
        result = subprocess.run([sys.executable, str(Path(checker.__file__)),
            '--binary', str(provider), '--output', str(output),
            '--relocatable-metadata', '--symbol-object', str(other),
            '--symbol-object', str(code)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.is_file())

    def test_cli_rejects_companion_objects_without_relocatable_mode(self):
        result = subprocess.run([sys.executable, str(Path(checker.__file__)),
            '--binary', str(self.object()), '--output', str(self.root / 'result.json'),
            '--symbol-object', str(self.object('code.o'))], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('requires --relocatable-metadata', result.stderr)
        self.assertFalse((self.root / 'result.json').exists())

    def test_cli_rejects_mixed_symbol_selection(self):
        code = self.object('code.o')
        result = subprocess.run([sys.executable, str(Path(checker.__file__)),
            '--binary', str(self.object()), '--output', str(self.root / 'result.json'),
            '--relocatable-metadata', '--symbols', str(code),
            '--symbol-object', str(code)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / 'result.json').exists())

    def test_companion_with_different_alias_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'one defined matching object symbol'):
            checker.inventory(self.object(defined=False), relocatable=True,
                              symbols=self.object('code.o', alias='$dtrace124.fn'))

    def test_defined_symbol_cannot_be_replaced_by_other_companion(self):
        with self.assertRaisesRegex(ValueError, 'bounded NOP/RET'):
            checker.inventory(self.object(bad_patch=True), relocatable=True,
                              symbols=self.object('other.o'))

    def test_wrong_relocation_kind_is_rejected(self):
        self.rejected('relocation semantics', kind=2)

    def test_out_of_bounds_symbol_reference_is_rejected(self):
        self.rejected('ELF relocation reference', symbol_index=999)

    def test_wrong_function_alias_is_rejected(self):
        self.rejected('actual function alias', alias='$dtrace123.other')

    def test_changed_instruction_is_rejected(self):
        self.rejected('bounded NOP/RET', bad_patch=True)

    def test_out_of_bounds_ordinary_site_is_rejected(self):
        self.rejected('bounded NOP/RET', site=4096)

    def test_out_of_bounds_enabled_site_is_rejected(self):
        self.rejected('bounded XOR/NOP', enabled_site=4096)

    def test_bad_function_bounds_are_rejected(self):
        self.rejected('exceeds its executable section', function_value=1)

    def test_unconsumed_relocation_is_rejected(self):
        self.rejected('unconsumed DOF ELF relocation', extra_relocation=True)

    def test_nonzero_unresolved_address_is_rejected(self):
        self.rejected('nonzero relocatable probe address', address=1)

    def test_foreign_architecture_is_rejected_explicitly(self):
        self.rejected('amd64 ET_REL', machine=183)

    def test_linked_default_metadata_keeps_existing_schema(self):
        result = checker.inventory(self.object(linked=True))
        self.assertNotIn('relocatable_metadata', result)
        self.assertEqual(result['probe_schemas'][0]['function'], 'fn')

    def test_cli_rejects_linked_address_claim_for_relocatable_mode(self):
        result = subprocess.run([sys.executable, str(Path(checker.__file__)),
            '--binary', str(self.object()), '--output', str(self.root / 'result.json'),
            '--relocatable-metadata', '--check-amd64-sites'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('does not establish linked load addresses', result.stderr)
        self.assertFalse((self.root / 'result.json').exists())


if __name__ == '__main__':
    unittest.main()
