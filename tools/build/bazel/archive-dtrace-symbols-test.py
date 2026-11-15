# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""DTrace archive comparisons must preserve definitions and references together."""
import copy
import importlib.util
from pathlib import Path
import unittest
import tempfile

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


fixture_spec = importlib.util.spec_from_file_location('dof_fixtures',
    Path(__file__).with_name('dtrace-relocatable-inventory-test.py'))
fixtures = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixtures)


class DofContexts(unittest.TestCase):
    def metadata(self, key, *, code=0x90, site=0, bad_patch=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.o'
            data = fixtures.fixture(alias='$dtrace' + key + '.fn', site=site, bad_patch=bad_patch)
            path.write_bytes(data)
            parsed = fixtures.checker.RelocatableDof.read(path)
            text = parsed['sections'][parsed['section_names'].index('.text')]
            data[text[4] + 5] = code  # Outside both checked patch sites.
            path.write_bytes(data)
            return fixtures.checker.inventory(path, relocatable=True)

    def contexts(self, key, **options):
        return checker.dof_alias_contexts(self.metadata(key, **options), '0:merged')

    def graphs(self):
        candidate = {'0:merged': [('$dtrace9.fn', 'T'), ('$dtrace8.fn', 'T')]}
        reference = {'0:merged': [('$dtrace1.fn', 'T'), ('$dtrace2.fn', 'T')]}
        a = self.contexts('9') | self.contexts('8', code=0x91)
        b = self.contexts('1') | self.contexts('2', code=0x91)
        return candidate, reference, a, b

    def test_real_dof_disambiguates_identical_symbol_graphs(self):
        a, b, ac, bc = self.graphs()
        result = checker.compare_archive_symbols(a, b, candidate_contexts=ac, reference_contexts=bc)
        self.assertEqual({(x['candidate_id'], x['reference_id']) for x in result}, {('9', '1'), ('8', '2')})
        self.assertTrue(all(x['validated_dof_context'] for x in result))

    def test_different_function_bytes_rejected(self):
        a, b, ac, bc = self.graphs(); ac['8'] = self.contexts('8', code=0x92)['8']
        with self.assertRaisesRegex(ValueError, 'symbols differ'):
            checker.compare_archive_symbols(a, b, candidate_contexts=ac, reference_contexts=bc)

    def test_missing_context_rejected(self):
        a, b, ac, bc = self.graphs(); del ac['8']
        with self.assertRaisesRegex(ValueError, 'symbols differ'):
            checker.compare_archive_symbols(a, b, candidate_contexts=ac, reference_contexts=bc)

    def test_absent_alias_context_rejected(self):
        a, b, ac, bc = self.graphs(); ac['404'] = ac['9']
        with self.assertRaisesRegex(ValueError, 'absent archive alias'):
            checker.compare_archive_symbols(a, b, candidate_contexts=ac, reference_contexts=bc)

    def test_duplicate_probe_context_rejected(self):
        metadata = self.metadata('9'); metadata['probe_locations'] *= 2
        with self.assertRaisesRegex(ValueError, 'unique emitted probe context'):
            checker.dof_alias_contexts(metadata, '0:merged')

    def test_ambiguous_provider_attributes_rejected(self):
        metadata = self.metadata('9'); metadata['providers'] *= 2
        with self.assertRaisesRegex(ValueError, 'unique provider attributes'):
            checker.dof_alias_contexts(metadata, '0:merged')

    def test_provider_attributes_drift_rejected(self):
        a, b, ac, bc = self.graphs(); metadata = self.metadata('9')
        metadata['providers'][0]['attributes'][0] = 1
        ac['9'] = checker.dof_alias_contexts(metadata, '0:merged')['9']
        with self.assertRaisesRegex(ValueError, 'symbols differ'):
            checker.compare_archive_symbols(a, b, candidate_contexts=ac, reference_contexts=bc)

    def test_site_offset_drift_rejected(self):
        a, b, ac, bc = self.graphs(); ac['9'] = self.contexts('9', site=1)['9']
        with self.assertRaisesRegex(ValueError, 'symbols differ'):
            checker.compare_archive_symbols(a, b, candidate_contexts=ac, reference_contexts=bc)

    def test_invalid_patch_bytes_rejected_before_mapping(self):
        with self.assertRaisesRegex(ValueError, 'bounded NOP/RET patch'):
            self.contexts('9', bad_patch=True)

    def test_member_binding_drift_rejected(self):
        a, b, ac, bc = self.graphs()
        ac['9'] = checker.dof_alias_contexts(self.metadata('9'), '1:other')['9']
        with self.assertRaisesRegex(ValueError, 'symbols differ'):
            checker.compare_archive_symbols(a, b, candidate_contexts=ac, reference_contexts=bc)


if __name__ == '__main__':
    unittest.main()
