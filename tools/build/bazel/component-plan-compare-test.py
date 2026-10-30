#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Ensure configuration comparison rejects missing work and altered inputs."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('comparison', Path(__file__).with_name('component-plan-compare.py'))
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.plan = dict(format=1, status='configured', components=[{'flags': ['-O2']}],
                         input_sha256={'source': 'abc'}, elapsed_seconds=1, configuration_jobs=1,
                         build_environment={'target': 'example', 'commands': [
                             {'argv': ['make', '-v', 'CFLAGS'], 'status': 0, 'stderr': ''},
                             {'argv': ['make', '-v', 'CFLAGS'], 'status': 0, 'stderr': ''},
                             {'argv': ['make', '-v', 'LIB'], 'status': 0, 'stderr': ''}]})

    def test_only_scheduling_differences_allowed(self):
        other = copy.deepcopy(self.plan)
        other['elapsed_seconds'] = 3
        other['configuration_jobs'] = 4
        other['build_environment']['commands'].reverse()
        self.assertEqual(comparison.compare(self.plan, other)['queries'], 3)

    def test_reject_changed_evidence(self):
        for kind in ('flags', 'hash', 'target', 'missing_repeat', 'failure', 'stderr', 'unknown'):
            other = copy.deepcopy(self.plan)
            if kind == 'flags': other['components'][0]['flags'] = ['-O0']
            elif kind == 'hash': other['input_sha256']['source'] = 'def'
            elif kind == 'target': other['build_environment']['target'] = 'other'
            elif kind == 'missing_repeat': other['build_environment']['commands'].pop(0)
            elif kind == 'failure': other['build_environment']['commands'][0]['status'] = 1
            elif kind == 'stderr': other['build_environment']['commands'][0]['stderr'] = 'warning'
            else: other['new_configuration_field'] = True
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                comparison.compare(self.plan, other)


if __name__ == '__main__':
    unittest.main()
