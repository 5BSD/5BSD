# SPDX-License-Identifier: BSD-2-Clause
"""Original archive input schema/integrity contracts; no Make build is mocked."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
import install_reference_libraries as lib


class LibraryInputs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR'])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.assertTrue(self.root.is_relative_to('/usr/obj'))
        self.source = self.root / 'source'
        self.component = self.source / 'libfixture'
        self.component.mkdir(parents=True)
        self.compiler = self.root / 'compiler'
        self.compiler.write_bytes(b'compiler fixture')
        self.reference = self.root / 'reference'
        self.reference.mkdir()
        self.artifact = self.reference / 'objects' / str(self.component).lstrip('/') / 'libfixture.a'
        self.artifact.parent.mkdir(parents=True)
        self.artifact.write_bytes(b'!<arch>\n')
        self.receipt = self.reference / 'receipt.json'
        self.info = dict(format=1, status='passed', target_architecture='aarch64', component=str(self.component),
            environment=dict(compiler_selected=str(self.compiler), input_sha256={str(self.compiler): lib.digest(self.compiler)}))
        self.manifest = self.root / 'libraries.json'
        self.config = dict(format=1, libraries={'LIBSA': dict(receipt=str(self.receipt), receipt_sha256='',
            artifact=str(self.artifact.relative_to(self.reference)), artifact_sha256=lib.digest(self.artifact))})
        self.refresh()

    def refresh(self):
        self.receipt.write_text(json.dumps(self.info))
        self.config['libraries']['LIBSA']['receipt_sha256'] = lib.digest(self.receipt)
        self.manifest.write_text(json.dumps(self.config))

    def load(self):
        return lib.load(self.manifest, 'aarch64', self.source, self.compiler)

    def test_valid_exact_bindings(self):
        records, bindings = self.load()
        self.assertEqual(records['LIBSA']['artifact'], str(self.artifact))
        self.assertEqual(bindings[str(self.artifact)], lib.digest(self.artifact))
        lib.verify(bindings)

    def test_receipt_state_architecture_and_format(self):
        original = copy.deepcopy(self.info)
        for field, value in [('status', 'failed'), ('target_architecture', 'riscv64'), ('format', True)]:
            with self.subTest(field=field):
                self.info = {**original, field: value}
                self.refresh()
                with self.assertRaisesRegex(ValueError, 'must pass'):
                    self.load()

    def test_receipt_and_artifact_corruption(self):
        self.receipt.write_text(self.receipt.read_text() + ' ')
        with self.assertRaisesRegex(ValueError, 'receipt digest'):
            self.load()
        self.refresh()
        self.artifact.write_bytes(b'!<arch>\nchanged')
        with self.assertRaisesRegex(ValueError, 'artifact digest'):
            self.load()

    def test_variable_and_path_contracts(self):
        item = self.config['libraries']['LIBSA']
        self.config['libraries'] = {'CC': item}
        self.manifest.write_text(json.dumps(self.config))
        with self.assertRaisesRegex(ValueError, 'LIB variable'):
            self.load()
        self.config['libraries'] = {'LIBSA': item}
        item['artifact'] = '../elsewhere.a'
        self.manifest.write_text(json.dumps(self.config))
        with self.assertRaisesRegex(ValueError, 'canonical relative'):
            self.load()
        for value in ['/usr/obj/a b', '/usr/obj/a$bad', '/usr/obj/a;bad', '/home/foreign']:
            with self.subTest(path=value), self.assertRaises((ValueError, FileNotFoundError)):
                lib.safe_path(value, True)
        with self.assertRaisesRegex(ValueError, 'under /usr/obj'):
            lib.safe_path('/tmp', True)

    def test_component_and_compiler_identity(self):
        original = copy.deepcopy(self.info)
        self.info['component'] = str(self.root)
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'source tree'):
            self.load()
        self.info = original
        self.compiler.write_bytes(b'changed compiler')
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'compiler differs'):
            self.load()

    def test_regular_archive_and_symlink(self):
        self.artifact.write_bytes(b'!<thin>\n')
        self.config['libraries']['LIBSA']['artifact_sha256'] = lib.digest(self.artifact)
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'regular original archive'):
            self.load()
        target = self.artifact.with_name('other.a')
        target.write_bytes(b'!<arch>\n')
        self.artifact.unlink()
        self.artifact.symlink_to(target)
        self.config['libraries']['LIBSA']['artifact_sha256'] = lib.digest(target)
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'object-tree artifact'):
            self.load()

    def shared_fixture(self, machine=183):
        self.artifact = self.artifact.with_name('libfixture.so.11')
        self.artifact.write_bytes(b'\x7fELF\x02\x01' + bytes(10) + (3).to_bytes(2, 'little') + machine.to_bytes(2, 'little'))
        item = self.config['libraries']['LIBSA']
        item.update(kind='shared', artifact=str(self.artifact.relative_to(self.reference)), artifact_sha256=lib.digest(self.artifact))
        self.refresh()
    def test_shared_library_kind_and_target_identity(self):
        self.shared_fixture()
        self.assertEqual(self.load()[0]['LIBSA']['kind'], 'shared')
        self.shared_fixture(machine=62)
        with self.assertRaisesRegex(ValueError, 'target ELF64'): self.load()
    def test_shared_library_cannot_be_archive_or_script(self):
        self.shared_fixture()
        for content in [b'!<arch>\n', b'GROUP ( another.so )']:
            self.artifact.write_bytes(content)
            self.config['libraries']['LIBSA']['artifact_sha256'] = lib.digest(self.artifact)
            self.refresh()
            with self.subTest(content=content), self.assertRaisesRegex(ValueError, 'target ELF64'): self.load()
    def header_fixture(self):
        directory = self.reference / 'stage/usr/include'
        directory.mkdir(parents=True)
        header = directory / 'fixture.h'
        header.write_text('/* original stage fixture */\n')
        metadata = self.reference / 'component.METALOG'
        metadata.write_text('./usr/include/fixture.h type=file sha256=' + lib.digest(header) + '\n')
        self.info['metadata_phases'] = {'component.METALOG': lib.digest(metadata)}
        self.config['libraries']['LIBSA']['include_directories'] = ['stage/usr/include']
        self.refresh()
        return directory, header
    def test_declared_stage_headers_and_added_file_detection(self):
        directory, _ = self.header_fixture()
        records, bindings = self.load()
        lib.verify(bindings); lib.verify_headers(records)
        (directory / 'shadow.h').write_text('changed search inventory')
        with self.assertRaisesRegex(ValueError, 'contents changed'): lib.verify_headers(records)
        with self.assertRaisesRegex(ValueError, 'differs from installation'): self.load()
    def test_header_metadata_and_payload_corruption(self):
        _, header = self.header_fixture()
        header.write_text('different payload')
        with self.assertRaisesRegex(ValueError, 'differs from installation'): self.load()
    def test_stage_headers_must_appear_in_compiler_dependencies(self):
        directory, header = self.header_fixture()
        records, _ = self.load()
        objects = self.root / 'consumer'; objects.mkdir()
        dependency = objects / '.depend.fixture.pieo'
        dependency.write_text('fixture.pieo: /elsewhere/fixture.h\n')
        with self.assertRaisesRegex(ValueError, 'absent from compiler dependencies'):
            lib.audit_header_dependencies(objects, records)
        dependency.write_text('fixture.pieo: ' + str(header) + '\n')
        self.assertEqual(len(lib.audit_header_dependencies(objects, records)[str(directory)]), 1)

    def test_include_directory_must_be_in_reference_stage(self):
        self.header_fixture()
        for value in ['../escape', 'objects', 'stage/../objects']:
            self.config['libraries']['LIBSA']['include_directories'] = [value]; self.refresh()
            with self.subTest(path=value), self.assertRaises(ValueError): self.load()

    def test_recheck_after_loading(self):
        _, bindings = self.load()
        self.artifact.write_bytes(b'!<arch>\nlate change')
        with self.assertRaisesRegex(ValueError, 'input changed'):
            lib.verify(bindings)


class CustomLinks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.objects = self.root / 'objects'
        self.objects.mkdir()
        self.archive = self.root / 'libsa.a'
        self.archive.write_bytes(b'!<arch>\n')
        self.libraries = {'LIBSA32': {'artifact': str(self.archive)}}
        self.output = self.objects / 'boot.out'
        self.output.write_bytes(b'completed output fixture')
        self.meta = self.objects / 'boot.out.meta'

    def metadata(self, command, cwd=None):
        self.meta.write_text('CMD ' + command + '\nCWD ' + str(cwd or self.objects) + '\n')

    def test_actual_link_operand_and_output_bound(self):
        self.metadata('ld -static -o boot.out entry.o ' + str(self.archive))
        result = lib.audit_links(self.objects, self.libraries)
        self.assertEqual(result['libraries'], {'LIBSA32': [str(self.meta)]})
        self.assertEqual(result['commands'][0]['output_sha256'], lib.digest(self.output))
        self.assertEqual(result['commands'][0]['metadata_sha256'], lib.digest(self.meta))

    def test_named_archive_search_is_bound(self):
        for search, library in [('-L' + str(self.root), '-lsa'),
                                ('-L ' + str(self.root), '-l sa'),
                                ('-L' + str(self.root), '-l:libsa.a')]:
            with self.subTest(search=search, library=library):
                self.metadata('cc -o boot.out entry.o ' + search + ' ' + library)
                self.assertEqual(set(lib.audit_links(self.objects, self.libraries)['libraries']), {'LIBSA32'})

    def test_earlier_archive_or_shared_library_cannot_witness_binding(self):
        earlier = self.root / 'earlier'
        earlier.mkdir()
        for filename in ['libsa.a', 'libsa.so']:
            with self.subTest(filename=filename):
                shadow = earlier / filename
                shadow.write_bytes(b'unrelated library')
                self.metadata('cc -o boot.out entry.o -L' + str(earlier) + ' -L' + str(self.root) + ' -lsa')
                with self.assertRaisesRegex(ValueError, 'absent from completed link'):
                    lib.audit_links(self.objects, self.libraries)
                shadow.unlink()
        shadow = self.root / 'libsa.so'
        shadow.write_bytes(b'shared preferred to archive')
        self.metadata('cc -o boot.out entry.o -L' + str(self.root) + ' -lsa')
        with self.assertRaisesRegex(ValueError, 'absent from completed link'):
            lib.audit_links(self.objects, self.libraries)

    def test_named_shared_search_matches_only_bound_target(self):
        shared = self.root / 'libsa.so.11'; shared.write_bytes(b'shared fixture')
        link = self.root / 'libsa.so'; link.symlink_to(shared.name)
        libraries = {'LIBSA': {'artifact': str(shared), 'kind': 'shared'}}
        self.metadata('cc -o boot.out entry.o -L' + str(self.root) + ' -lsa')
        self.assertEqual(set(lib.audit_links(self.objects, libraries)['libraries']), {'LIBSA'})
        other = self.root / 'libother.so.11'; other.write_bytes(b'shadow')
        link.unlink(); link.symlink_to(other.name)
        with self.assertRaisesRegex(ValueError, 'absent from completed link'):
            lib.audit_links(self.objects, libraries)

    def test_named_search_modes_and_response_files_fail_closed(self):
        for extra in ['@link.rsp', '-Wl,-Bstatic', '-static', '-Wl,-L/elsewhere', '--library-path=/elsewhere']:
            with self.subTest(extra=extra):
                self.metadata('cc -o boot.out entry.o -L' + str(self.root) + ' -lsa ' + extra)
                with self.assertRaisesRegex(ValueError, 'absent from completed link'):
                    lib.audit_links(self.objects, self.libraries)

    def test_missing_search_path_is_not_a_default_library_witness(self):
        self.metadata('cc -o boot.out entry.o -lsa')
        with self.assertRaisesRegex(ValueError, 'absent from completed link'):
            lib.audit_links(self.objects, self.libraries)

    def test_unused_archive_and_compile_are_rejected(self):
        for command in ['ld -o boot.out entry.o',
                        'cc -c -o boot.out ' + str(self.archive),
                        'echo -o boot.out ' + str(self.archive),
                        'ld -o boot.out entry.o ; echo ' + str(self.archive),
                        'ld -o boot.out entry.o&&echo ' + str(self.archive)]:
            with self.subTest(command=command):
                self.metadata(command)
                with self.assertRaisesRegex(ValueError, 'absent from completed link'):
                    lib.audit_links(self.objects, self.libraries)

    def test_output_and_directory_escape_are_rejected(self):
        outside = self.root / 'outside.out'
        outside.write_bytes(b'outside')
        self.metadata('ld -o ' + str(outside) + ' ' + str(self.archive))
        with self.assertRaisesRegex(ValueError, 'output differs'):
            lib.audit_links(self.objects, self.libraries)
        self.metadata('ld -o boot.out ' + str(self.archive), cwd=self.root)
        with self.assertRaisesRegex(ValueError, 'CWD escapes'):
            lib.audit_links(self.objects, self.libraries)

    def test_different_existing_target_is_rejected(self):
        other = self.objects / 'other.out'
        other.write_bytes(b'other')
        self.metadata('ld -o other.out ' + str(self.archive))
        with self.assertRaisesRegex(ValueError, 'output differs'):
            lib.audit_links(self.objects, self.libraries)


if __name__ == '__main__':
    unittest.main()
