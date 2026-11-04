#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Validate the independent Make oracle's restricted presence-only selectors."""
from pathlib import Path
import os
import subprocess
import tempfile
import sys
import unittest
from install_reference_options import component_definitions, validate_metadata_component, audit_generated_headers


class ComponentDefinitionsTests(unittest.TestCase):
    def test_actual_traceroute_selector_is_exact_presence_value(self):
        self.assertEqual(component_definitions(Path('/usr/src/usr.sbin/traceroute'),
            ['TRACEROUTE_NO_IPSEC']), {'TRACEROUTE_NO_IPSEC': '1'})

    def test_namespaces_follow_selected_component(self):
        self.assertEqual(component_definitions(Path('/usr/src/a/foo-bar'), ['FOO_BAR_DEBUG']),
                         {'FOO_BAR_DEBUG': '1'})
        with self.assertRaisesRegex(ValueError, 'namespace'):
            component_definitions(Path('/usr/src/usr.sbin/traceroute6'), ['TRACEROUTE_NO_IPSEC'])

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


if __name__ == '__main__':
    unittest.main()
