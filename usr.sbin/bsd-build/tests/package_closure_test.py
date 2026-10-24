# SPDX-License-Identifier: BSD-2-Clause
"""Selected-package metadata checks; no host providers or solver assumptions."""
import copy
import importlib.util
import os
from pathlib import Path
import unittest

helper = os.environ.get('BSD_BUILD_CLOSURE_HELPER') or str(
    Path(__file__).resolve().parents[3] / 'tools/build/capimage/package_closure.py')
spec = importlib.util.spec_from_file_location('package_closure', helper)
closure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(closure)


class Closure(unittest.TestCase):
    def setUp(self):
        self.runtime = dict(name='runtime', origin='lang/runtime', version='2',
                            shlibs_provided=['libruntime.so.2'])
        self.app = dict(name='app', origin='apps/app', version='1',
                        deps={'runtime': dict(origin='lang/runtime', version='1')},
                        shlibs_required=['libruntime.so.2'])

    def test_selected_generator_and_recorded_version(self):
        # A recorded dependency version is not an exact solver constraint.
        for version in ('0.9', '2'):
            self.runtime['version'] = version
            closure.require_selected_set(iter([self.app, self.runtime]))

    def test_missing_and_wrong_origin(self):
        with self.assertRaisesRegex(ValueError, 'lacks dependencies'):
            closure.require_selected_set([self.app])
        self.runtime['origin'] = 'other/runtime'
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            closure.require_selected_set([self.app, self.runtime])

    def test_transitive_dependency(self):
        self.runtime['deps'] = {'leaf': dict(origin='libs/leaf', version='1')}
        with self.assertRaisesRegex(ValueError, 'lacks dependencies.*runtime'):
            closure.require_selected_set([self.app, self.runtime])
        closure.require_selected_set([self.app, self.runtime,
                                     dict(name='leaf', origin='libs/leaf')])

    def test_invalid_identity_and_dependency_records(self):
        for record in (None, {}, dict(name=''), dict(name=True)):
            with self.subTest(record=record), self.assertRaises(ValueError):
                closure.require_selected_set([record])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            closure.require_selected_set([self.runtime, copy.deepcopy(self.runtime)])
        for deps in ([], {'runtime': {}}, {'runtime': dict(origin='', version='1')},
                     {'runtime': dict(origin='lang/runtime', version=False)}):
            self.app['deps'] = deps
            with self.subTest(deps=deps), self.assertRaises(ValueError):
                closure.require_selected_set([self.app, self.runtime])

    def test_library_provider_must_be_selected_and_match(self):
        for providers in ([], ['libruntime.so.1'], ['libruntime.so.2:32']):
            self.runtime['shlibs_provided'] = providers
            with self.subTest(providers=providers), self.assertRaisesRegex(
                    ValueError, 'lacks shared-library providers'):
                closure.require_selected_set([self.app, self.runtime])
        closure.require_selected_set([dict(name='self',
            shlibs_required=['libself.so.1'], shlibs_provided=['libself.so.1'])])

    def test_invalid_library_metadata(self):
        for field in ('shlibs_provided', 'shlibs_required'):
            for value in ('lib.so.1', [None], [''], ['../lib.so.1'],
                          ['lib.so.1'] * 2, ['lib\n.so.1']):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    closure.require_selected_set([dict(name='bad', **{field: value})])

    def test_selected_conflict_and_unselected_conflict(self):
        self.app['conflicts'] = ['runtime']
        with self.assertRaisesRegex(ValueError, 'declare package conflicts'):
            closure.require_selected_set([self.app, self.runtime])
        self.app['conflicts'] = ['not-selected']
        closure.require_selected_set([self.app, self.runtime])

    def test_malformed_conflicts(self):
        for value in ('runtime', [None], [''], ['bad\nname']):
            self.app['conflicts'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'invalid package conflicts'):
                closure.require_selected_set([self.app, self.runtime])


if __name__ == '__main__':
    unittest.main()
