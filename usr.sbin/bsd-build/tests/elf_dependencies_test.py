# SPDX-License-Identifier: BSD-2-Clause
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

helper = os.environ.get('BSD_BUILD_ELF_HELPER') or str(
    Path(__file__).resolve().parents[3] / 'tools/build/capimage/elf_dependencies.py')
spec = importlib.util.spec_from_file_location('elf_dependencies', helper)
elf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf)


def fixture(bits=64, order='<', extra=(), interp=b'/libexec/ld-elf.so.1\0', null=True):
    cls=1 if bits==32 else 2
    hf=order+('HHIIIIIHHHHHH' if cls==1 else 'HHIQQQIHHHHHH')
    pf=order+('IIIIIIII' if cls==1 else 'IIQQQQQQ')
    df=order+('iI' if cls==1 else 'qQ')
    eh=16+struct.calcsize(hf); ps=struct.calcsize(pf)
    data=bytearray(1024); data[:16]=b'\x7fELF'+bytes([cls,1 if order=='<' else 2,1])+bytes(9)
    data[16:eh]=struct.pack(hf,3,62,1,0,eh,0,0,eh,ps,3,0,0,0)
    table=b'\0libfixture.so\0$ORIGIN/../lib\0'
    tags=[(5,0x1000+896),(10,len(table)),(1,1),(29,15),*extra]
    if null: tags.append((0,0))
    dynamic=b''.join(struct.pack(df,*tag) for tag in tags)
    for index,(typ,off,size) in enumerate([(1,0,len(data)),(3,512,len(interp)),(2,640,len(dynamic))]):
        values=(typ,off,0x1000+off,0,size,size,5,1) if cls==1 else (typ,5,off,0x1000+off,0,size,size,1)
        data[eh+index*ps:eh+(index+1)*ps]=struct.pack(pf,*values)
    data[512:512+len(interp)]=interp; data[640:640+len(dynamic)]=dynamic
    data[896:896+len(table)]=table
    return bytes(data)


class Metadata(unittest.TestCase):
    def test_classes_endianness_and_no_sections(self):
        for bits in (32,64):
            for order in ('<','>'):
                with self.subTest(bits=bits,order=order):
                    row=elf.inspect(fixture(bits,order))
                    self.assertEqual(row['elf_class'],bits)
                    self.assertEqual(row['needed'],['libfixture.so'])
                    self.assertEqual(row['runpath'],'$ORIGIN/../lib')
                    self.assertEqual(row['interpreter'],'/libexec/ld-elf.so.1')
                    self.assertFalse(row['dependency_coverage_complete'])

    def test_feature_control_notes_record_all_occurrences(self):
        for bits in (32, 64):
            for order in ('<', '>'):
                with self.subTest(bits=bits, order=order):
                    def with_notes(blob):
                        data = bytearray(fixture(bits, order))
                        hf = order + ('HHIIIIIHHHHHH' if bits == 32 else 'HHIQQQIHHHHHH')
                        pf = order + ('IIIIIIII' if bits == 32 else 'IIQQQQQQ')
                        eh, ps = 16 + struct.calcsize(hf), struct.calcsize(pf)
                        header = list(struct.unpack(hf, data[16:eh]))
                        header[9] = 4
                        data[16:eh] = struct.pack(hf, *header)
                        off = len(data)
                        values = ((4, off, 0, 0, len(blob), len(blob), 0, 4)
                                  if bits == 32 else (4, 0, off, 0, 0, len(blob), len(blob), 4))
                        data[eh+3*ps:eh+4*ps] = struct.pack(pf, *values)
                        return bytes(data) + blob
                    def note(value):
                        return struct.pack(order + 'III', 8, 4, 4) + b'FreeBSD\0' + struct.pack(order + 'I', value)
                    row = elf.inspect(with_notes(note(0) + note(0x80000008)))
                    self.assertEqual([item['value'] for item in row['freebsd_feature_control_notes']], [0, 0x80000008])
                    self.assertEqual([item['offset'] for item in row['freebsd_feature_control_notes']], [1024, 1048])
                    for blob in (note(1)[:-1], b'x', struct.pack(order + 'III', 8, 8, 4) + b'FreeBSD\0' + bytes(8)):
                        with self.assertRaises(ValueError):
                            elf.inspect(with_notes(blob))
        self.assertEqual(elf.inspect(fixture())['freebsd_feature_control_notes'], [])

    def test_loader_flags_accumulate_without_discarding_unknown_bits(self):
        for bits in (32, 64):
            for order in ('<', '>'):
                with self.subTest(bits=bits, order=order):
                    # ORIGIN and NODEFLIB affect target library lookup. Extra
                    # bits must survive, including above the 32-bit range.
                    unknown = 1 << (bits - 1)
                    row = elf.inspect(fixture(bits, order, extra=[
                        (30, 1), (30, unknown),
                        (0x6ffffffb, 0x80), (0x6ffffffb, 0x800)]))
                    self.assertEqual(row['dynamic_flags'], 1 | unknown)
                    self.assertEqual(row['dynamic_flags_1'], 0x880)
        row = elf.inspect(fixture())
        self.assertEqual(row['dynamic_flags'], 0)
        self.assertEqual(row['dynamic_flags_1'], 0)

    def test_filter_and_audit_inputs_retained(self):
        row=elf.inspect(fixture(extra=[(tag,1) for tag in (0x7ffffffd,0x7fffffff,0x6ffffefb,0x6ffffefc)]))
        for key in ('auxiliary','filters','dependency_audit','audit'):
            self.assertEqual(row[key],['libfixture.so'])

    def test_malformed_objects_rejected(self):
        cases=[b'', b'not elf',fixture()[:80],fixture()[:-1],
               fixture(interp=b'/loader'),fixture(interp=b'/loader\0junk\0'),
               fixture(extra=[(5,0x1300)]),fixture(extra=[(1,9999)]),
               fixture(extra=[(1,0)]),fixture(null=False)]
        for index,data in enumerate(cases):
            with self.subTest(index=index),self.assertRaises(ValueError): elf.inspect(data)

    def test_dynamic_file_offset_must_match_loaded_address(self):
        data=bytearray(fixture())
        # PT_DYNAMIC's advertised file offset still contains valid tags, but
        # its virtual address selects different bytes after PT_LOAD mapping.
        struct.pack_into('<Q',data,64+2*56+16,0x1000+800)
        with self.assertRaisesRegex(ValueError,'dynamic.*mapping'):
            elf.inspect(bytes(data))

    def test_partial_file_and_zero_fill_overlap_rejected(self):
        for address in (0x1000+650,0x1000+900):
            for filesz in (0,4):
                with self.subTest(address=address,filesz=filesz):
                    data=bytearray(fixture())
                    # Replace PT_INTERP with another load touching only part
                    # of a metadata region; a whole-region match misses it.
                    struct.pack_into('<IIQQQQQQ',data,64+56,1,4,500,address,0,filesz,8,1)
                    with self.assertRaisesRegex(ValueError,'unique file-backed mapping'):
                        elf.inspect(bytes(data))

    def test_wrapped_virtual_load_range_rejected(self):
        data=bytearray(fixture())
        struct.pack_into('<Q',data,64+16,2**64-512)
        with self.assertRaisesRegex(ValueError,'address range'):
            elf.inspect(bytes(data))

    def test_empty_search_path_preserved(self):
        data=bytearray(fixture())
        struct.pack_into('<Q',data,640+3*16+8,0)
        row=elf.inspect(bytes(data))
        self.assertEqual(row['runpath'],'')
        self.assertIsNone(row['rpath'])

    def test_real_executable_feature_notes_match_elfctl(self):
        # Only edit a disposable fixture. It is inspected, never executed.
        with tempfile.TemporaryDirectory(prefix='elf-feature-notes-') as directory:
            work = Path(directory)
            source, target = work / 'main.c', work / 'main'
            source.write_text('int main(void) { return 0; }\n')
            result = subprocess.run(['cc', str(source), '-o', str(target)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for setting, expected in (('=wxneeded', 8), ('+noaslr', 9), ('-wxneeded', 1), ('-noaslr', 0)):
                with self.subTest(setting=setting):
                    result = subprocess.run([os.environ.get('BSD_BUILD_ELFCTL', 'elfctl'), '-e', setting, str(target)],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    notes = elf.inspect(target.read_bytes())['freebsd_feature_control_notes']
                    self.assertEqual(len(notes), 1)
                    self.assertEqual(notes[0]['value'], expected)
                    self.assertLess(notes[0]['offset'], target.stat().st_size)

    def test_real_linked_object(self):
        with tempfile.TemporaryDirectory(prefix='elf-metadata-') as directory:
            work=Path(directory); source=work/'library.c'; target=work/'library.so'
            source.write_text('int fixture(void) { return 7; }\n')
            p=subprocess.run(['cc','-shared','-fPIC','-Wl,-soname,libfixture.so',
                              '-Wl,-rpath,/explicit/search', '-Wl,-z,origin',
                              '-Wl,-z,nodefaultlib', str(source),'-o',str(target)],capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
            row=elf.inspect(target.read_bytes())
            self.assertEqual(row['soname'],'libfixture.so')
            self.assertIn('/explicit/search',(row['rpath'],row['runpath']))
            self.assertIsNone(row['interpreter'])
            self.assertTrue(row['dynamic_flags'] & 1)
            self.assertTrue(row['dynamic_flags_1'] & 0x800)

if __name__=='__main__': unittest.main()
