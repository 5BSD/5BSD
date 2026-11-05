#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Validate the independent Make oracle's restricted presence-only selectors."""
from pathlib import Path
import os
import subprocess
import tempfile
import sys
import unittest
from install_reference_options import component_definitions, validate_metadata_component, audit_generated_headers, audit_staged_metadata, METADATA_MODE


class ComponentDefinitionsTests(unittest.TestCase):
    def test_actual_traceroute_selector_is_exact_presence_value(self):
        self.assertEqual(component_definitions(Path('/usr/src/usr.sbin/traceroute'),
            ['TRACEROUTE_NO_IPSEC']), {'TRACEROUTE_NO_IPSEC': '1'})

    def test_namespaces_follow_selected_component(self):
        self.assertEqual(component_definitions(Path('/usr/src/a/foo-bar'), ['FOO_BAR_DEBUG']),
                         {'FOO_BAR_DEBUG': '1'})
        with self.assertRaisesRegex(ValueError, 'namespace'):
            component_definitions(Path('/usr/src/usr.sbin/traceroute6'), ['TRACEROUTE_NO_IPSEC'])

    def test_boot_component_selectors_remain_scoped_and_presence_only(self):
        component = Path('/usr/src/stand/i386/pxeldr')
        names = ['BOOT_PXELDR_PROBE_KEYBOARD', 'BOOT_PXELDR_ALWAYS_SERIAL']
        self.assertEqual(component_definitions(component, names), {name:'1' for name in names})
        for name in ['BOOT_PXELDR_', 'BOOT_LOADER_FLAGS', 'BOOT_PXELDR_PROBE_KEYBOARD=0']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                component_definitions(component, [name])
        with self.assertRaisesRegex(ValueError, 'collides'):
            component_definitions(component, names, profile_names=[names[0]])

    def test_arbitrary_assignments_and_make_expansions_are_rejected(self):
        for name in ['TRACEROUTE_NO_IPSEC=0', 'TRACEROUTE_$(CC)', 'TRACEROUTE_X\nY',
                     'traceroute_no_ipsec', 'TRACEROUTE_X Y', '', None]:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'identifier'):
                component_definitions(Path('/usr/src/usr.sbin/traceroute'), [name])

    def test_global_identity_paths_and_options_cannot_be_defined(self):
        for component, name in [('target', 'TARGET_ARCH'), ('machine', 'MACHINE_ARCH'),
                                ('src', 'SRC_ENV_CONF'), ('reference', 'REFERENCE_OBJROOT'),
                                ('ccache', 'CCACHE_DIR'), ('mk', 'MK_TESTS'),
                                ('without', 'WITHOUT_NIS'), ('make', 'MAKE_JOBS')]:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'global'):
                component_definitions(Path('/usr/src') / component, [name])
        for name in ['CC', 'DESTDIR', 'METALOG', 'SRCCONF', 'PATH']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                component_definitions(Path('/usr/src/usr.sbin/traceroute'), [name])

    def test_duplicates_and_option_profile_collisions_are_rejected(self):
        name = 'TRACEROUTE_NO_IPSEC'; component = Path('/usr/src/usr.sbin/traceroute')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            component_definitions(component, [name, name])
        with self.assertRaisesRegex(ValueError, 'collides'):
            component_definitions(component, [name], option_names=[name])
        with self.assertRaisesRegex(ValueError, 'collides'):
            component_definitions(component, [name], profile_names=[name])

    def test_metadata_mode_does_not_accept_arbitrary_make_assignments(self):
        helper = Path(__file__).with_name('install-reference.py')
        command = [sys.executable, '-B', str(helper), '--src', '/nonexistent',
                   '--objtop', '/nonexistent', '--profile', '/nonexistent',
                   '--component', '/nonexistent', '--output', '/nonexistent', '--jobs', '1']
        for value in ('filemon', 'normal', 'meta missing-meta=yes'):
            with self.subTest(value=value):
                result = subprocess.run(command + ['--make-meta=' + value],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertIn('--make-meta', result.stderr)
                self.assertIn('ignored explicit argument', result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_no_defines_preserves_existing_component_behavior(self):
        self.assertEqual(component_definitions(Path('/usr/src/123'), []), {})


class MetadataDirectoryTests(unittest.TestCase):
    def query(self, definitions):
        if 'TEST_SRCDIR' in os.environ:
            make = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE'] / 'usr.bin/bmake/make'
        else:
            make = Path('/usr/bin/make')
        self.assertTrue(make.is_file(), 'declared native bmake required in Bazel')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'Makefile').write_text(definitions + '\nall:\n\t@echo unsafe > recipe-executed\n')
            def query(arguments):
                return subprocess.run([str(make), '-r', '-C', str(root), *arguments],
                                      capture_output=True, text=True, check=True).stdout
            try:
                return validate_metadata_component(query)
            finally:
                self.assertFalse((root / 'recipe-executed').exists())

    def test_no_object_definedness_rejects_empty_or_no_values(self):
        for definitions in ('NO_OBJ=', 'NO_OBJ=no', 'NOOBJ=', 'NOOBJ=no', 'NO_OBJ=\nNOOBJ='):
            with self.subTest(definitions=definitions), self.assertRaisesRegex(ValueError, 'NO_OBJ/NOOBJ'):
                self.query(definitions)

    def test_object_component_query_does_not_run_recipe(self):
        self.assertIsNone(self.query('UNRELATED=yes'))

    def test_nested_source_directory_skips_logs_but_object_directory_records(self):
        if 'TEST_SRCDIR' in os.environ:
            make = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE'] / 'usr.bin/bmake/make'
        else:
            make = Path('/usr/bin/make')
        self.assertTrue(make.is_file(), 'declared native bmake required in Bazel')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, objects = root / 'source', root / 'objects'
            source.mkdir(); objects.mkdir()
            makefile = source / 'Makefile'
            makefile.write_text('.OBJDIR: ${OBJECT_DIRECTORY:U${.CURDIR}}\nprobe:\n\t@echo observed\n')
            original = makefile.read_bytes()
            for directory in (source, objects):
                result = subprocess.run([str(make), '-r', '-C', str(source),
                    'OBJECT_DIRECTORY=' + str(directory), '.MAKE.MODE=' + METADATA_MODE, 'probe'],
                    capture_output=True, text=True, check=True, timeout=10)
                self.assertEqual(result.stdout.strip(), 'observed')
            self.assertEqual(list(source.iterdir()), [makefile])
            self.assertEqual(makefile.read_bytes(), original)
            metadata = (objects / 'probe.meta').read_text()
            self.assertIn('CMD @echo observed', metadata)
            self.assertIn('CWD ' + str(objects), metadata)

    def test_ambiguous_directory_policy_fails_closed(self):
        for output in ('', 'no\n', 'no\nmaybe\n', 'no\nno\nno\n'):
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, 'ambiguous'):
                validate_metadata_component(lambda arguments: output)


class GeneratedHeaderTests(unittest.TestCase):
    def fixture(self, root, *, consumed_local=False, same=False):
        obj = root / 'reference'; sdk = root / 'sdk'
        obj.mkdir(); (sdk / 'stand').mkdir(parents=True)
        local = obj / 'ta.h'; old = sdk / 'stand/ta.h'
        local.write_text('#define BUILD_UTC 2\n')
        old.write_text(local.read_text() if same else '#define BUILD_UTC 1\n')
        selected = local if consumed_local else old
        (obj / '.depend.vets.o').write_text('vets.o: ' + str(selected) + '\n')
        return obj, sdk

    def test_changed_generated_input_cannot_use_old_sdk_header_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            obj, sdk = self.fixture(Path(directory))
            with self.assertRaisesRegex(ValueError, 'stale SDK generated header'):
                audit_generated_headers(obj, sdk)

    def test_identical_sdk_alias_is_recorded_but_not_accepted_for_local_request(self):
        with tempfile.TemporaryDirectory() as directory:
            obj, sdk = self.fixture(Path(directory), same=True)
            result = audit_generated_headers(obj, sdk)
            self.assertEqual(len(result['equivalent_external_generated_headers']), 1)
            with self.assertRaisesRegex(ValueError, 'was shadowed'):
                audit_generated_headers(obj, sdk, ['ta.h'])

    def test_explicit_local_consumption_binds_header_and_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            obj, sdk = self.fixture(Path(directory), consumed_local=True)
            result = audit_generated_headers(obj, sdk, ['ta.h'])
            self.assertEqual(result['required']['ta.h']['path'], str(obj / 'ta.h'))
            self.assertEqual(result['required']['ta.h']['dependencies'], [str(obj / '.depend.vets.o')])

    def test_missing_or_unconsumed_local_header_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            obj, sdk = self.fixture(Path(directory), consumed_local=True)
            with self.assertRaisesRegex(ValueError, 'missing regular'):
                audit_generated_headers(obj, sdk, ['missing.h'])
            (obj / '.depend.vets.o').write_text('vets.o: source.c\n')
            with self.assertRaisesRegex(ValueError, 'not consumed'):
                audit_generated_headers(obj, sdk, ['ta.h'])


class StagedMetadataTests(unittest.TestCase):
    def test_recorded_payload_and_replaced_symlink_are_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'include').mkdir()
            (root / 'include/header.h').write_bytes(b'header')
            (root / 'alias').symlink_to('include/header.h')
            import hashlib
            checksum = hashlib.sha256(b'header').hexdigest()
            result = audit_staged_metadata(root,
                './include type=dir\n./include/header.h type=file size=6 sha256=' + checksum +
                '\n./alias type=file\n./alias type=link link=include/header.h\n')
            self.assertEqual((result['record_claims'], result['unique_objects'], result['sha256_files']), (4, 3, 1))

    def test_out_of_stage_sdk_install_cannot_pass_as_a_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage, sdk = root / 'stage', root / 'sdk'
            stage.mkdir(); sdk.mkdir()
            (sdk / 'header.h').write_bytes(b'header')
            with self.assertRaisesRegex(ValueError, 'missing'):
                audit_staged_metadata(stage, './sdk/header.h type=file size=6\n')

    def test_parent_symlink_escape_and_traversal_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage, outside = root / 'stage', root / 'outside'
            stage.mkdir(); outside.mkdir()
            (outside / 'header.h').write_bytes(b'header')
            (stage / 'include').symlink_to(outside, target_is_directory=True)
            for metadata in ['./include/header.h type=file\n', './../outside/header.h type=file\n']:
                with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                    audit_staged_metadata(stage, metadata)

    def test_file_type_digest_size_and_link_mismatches_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'file').write_bytes(b'header')
            (root / 'link').symlink_to('file')
            for metadata in ['./link type=file\n', './file type=file size=7\n',
                             './file type=file sha256=' + '0' * 64 + '\n',
                             './link type=link link=other\n']:
                with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                    audit_staged_metadata(root, metadata)


if __name__ == '__main__':
    unittest.main()
