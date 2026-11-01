#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Validate the independent Make oracle's restricted presence-only selectors."""
from pathlib import Path
import unittest
from install_reference_options import component_definitions


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

    def test_no_defines_preserves_existing_component_behavior(self):
        self.assertEqual(component_definitions(Path('/usr/src/123'), []), {})


if __name__ == '__main__':
    unittest.main()
