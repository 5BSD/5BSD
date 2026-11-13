# SPDX-License-Identifier: BSD-2-Clause
"""DTrace archive comparisons must preserve definitions and references together."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('checker', Path(__file__).with_name('elf-artifact-check.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def graph(key='123'):
    return {'code': [('ordinary', 'T'), ('$dtrace' + key + '.helper', 'T')],
            'provider': [('$dtrace' + key + '.helper', 'U')]}


class AliasContracts(unittest.TestCase):
    def reject(self, candidate, reference=None, message='symbols differ'):
        with self.assertRaisesRegex(ValueError, message):
            checker.compare_archive_symbols(candidate, reference or graph())

    def test_identical(self):
        self.assertEqual(checker.compare_archive_symbols(graph(), graph()), [])

    def test_consistent_path_id_change(self):
        mapping = checker.compare_archive_symbols(graph('987'), graph())
        self.assertEqual(mapping, [{'candidate_id': '987', 'reference_id': '123',
            'incidence': (('code', 'helper', 'T'), ('provider', 'helper', 'U'))}])

    def test_broken_reference(self):
        candidate = graph('987')
        candidate['provider'] = [('$dtrace654.helper', 'U')]
        self.reject(candidate)

    def test_missing_reference(self):
        candidate = graph('987'); candidate['provider'] = []
        self.reject(candidate)

    def test_definition_moved_to_other_member(self):
        candidate = graph('987'); candidate['other'] = candidate.pop('code')
        self.reject(candidate)

    def test_wrong_symbol_kind(self):
        candidate = graph('987'); candidate['code'][1] = ('$dtrace987.helper', 'W')
        self.reject(candidate)

    def test_function_name_change(self):
        candidate = {member: [(name.replace('helper', 'other'), kind) for name, kind in entries]
                     for member, entries in graph('987').items()}
        self.reject(candidate)

    def test_ordinary_symbol_change(self):
        candidate = graph('987'); candidate['code'][0] = ('ordinary_drift', 'T')
        self.reject(candidate)

    def test_ordinary_symbol_multiplicity(self):
        candidate = graph('987'); candidate['code'].append(('ordinary', 'T'))
        self.reject(candidate)

    def test_alias_groups_cannot_merge(self):
        reference = graph()
        reference['code'].append(('$dtrace456.second', 'T'))
        reference['provider'].append(('$dtrace456.second', 'U'))
        candidate = graph('987')
        candidate['code'].append(('$dtrace987.second', 'T'))
        candidate['provider'].append(('$dtrace987.second', 'U'))
        self.reject(candidate, reference)

    def test_ambiguous_mapping_is_rejected(self):
        reference = graph()
        reference['code'].append(('$dtrace456.helper', 'T'))
        reference['provider'].append(('$dtrace456.helper', 'U'))
        candidate = copy.deepcopy(reference)
        candidate['code'][1] = ('$dtrace987.helper', 'T')
        candidate['provider'][0] = ('$dtrace987.helper', 'U')
        self.reject(candidate, reference, 'ambiguous DTrace')

    def test_nondigit_prefix_is_not_an_alias(self):
        candidate = graph('other')
        self.reject(candidate)


if __name__ == '__main__':
    unittest.main()
