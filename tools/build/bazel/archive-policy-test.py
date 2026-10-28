#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
import unittest
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from archive_policy import resolve

class DirectoryPolicyTests(unittest.TestCase):
    def request(self, mode='0755'):
        return dict(users={}, groups={}, passwd='passwd', group='group', mtree='mtree',
                    mtree_specs=[dict(source='spec', prefix='/')],
                    records=[dict(destination='/', type='dir', owner='root', group='wheel', mode=mode, tags=[]),
                             dict(destination='/created', type='dir', owner='root', group='wheel', mode='0755', tags=[]),
                             dict(destination='/created/file', type='file')])
    def check(self, request):
        with patch('archive_policy.accounts', return_value={'root':0,'wheel':0}), patch('archive_policy.subprocess.run', return_value=SimpleNamespace(stdout='. type=dir uname=root gname=wheel mode=0755\n')):
            return resolve(request)
    def test_explicit_directory_and_matching_overlap(self):
        result=self.check(self.request())
        self.assertEqual(len(result['records']),3)
    def test_conflicting_overlap(self):
        with self.assertRaisesRegex(ValueError,'conflicts with mtree'):
            self.check(self.request('0777'))
    def test_duplicate(self):
        r=self.request();r['records'].append(dict(r['records'][1]))
        with self.assertRaisesRegex(ValueError,'duplicate explicit'):
            self.check(r)
    def test_missing_ancestor(self):
        r=self.request();r['records'][-1]['destination']='/missing/file'
        with self.assertRaisesRegex(ValueError,'missing source directory'):
            self.check(r)
    def test_package_owned_empty_directory_and_ancestors(self):
        r=self.request();r['directory_packages']=['example']
        flattened = ('./state type=dir uname=root gname=wheel mode=0755\n'
                     './state/empty type=dir uname=root gname=wheel mode=0700 tags=package=example\n'
                     './unrelated type=dir uname=root gname=wheel mode=0755 tags=package=other\n')
        with patch('archive_policy.accounts', return_value={'root':0,'wheel':0}), patch('archive_policy.subprocess.run', return_value=SimpleNamespace(stdout=flattened)):
            result=resolve(r)
            entries={entry['destination']:entry for entry in result['records']}
            self.assertIn('/state', entries)
            self.assertEqual(entries['/state/empty']['mode'], '0700')
            self.assertEqual(entries['/state/empty']['tags'], ['package=example'])
            self.assertNotIn('/unrelated', entries)
            r.pop('directory_packages')
            self.assertEqual(resolve(r)['records'], r['records'])
    def test_package_directory_selection_requires_source(self):
        r=self.request();r['directory_packages']=['example'];r['mtree_specs']=[]
        with self.assertRaisesRegex(ValueError, 'requires mtree'):
            resolve(r)
    def test_supplemental_policy_cannot_override_directory_mode(self):
        r=self.request();r['records'][-1]['destination']='/custom/file'
        r['mtree_specs'].append(dict(source='extra', prefix='/'))
        outputs=[SimpleNamespace(stdout='./custom type=dir uname=root gname=wheel mode=0755\n'),
                 SimpleNamespace(stdout='./custom type=dir uname=root gname=wheel mode=0777\n')]
        with patch('archive_policy.accounts', return_value={'root':0,'wheel':0}), patch('archive_policy.subprocess.run', side_effect=outputs):
            with self.assertRaisesRegex(ValueError, 'conflicting mtree directory'):
                resolve(r)
    def test_native_mtree_runtime_is_scoped_to_child(self):
        with tempfile.TemporaryDirectory() as directory:
            library = Path(directory) / 'libfixture.so.1'
            library.write_bytes(b'fixture')
            request = self.request()
            request['mtree_runtime_libraries'] = [str(library)]
            with patch.dict(os.environ, {'LD_LIBRARY_PATH': '/inherited'}), patch('archive_policy.accounts', return_value={'root': 0, 'wheel': 0}), patch('archive_policy.subprocess.run', return_value=SimpleNamespace(stdout='. type=dir uname=root gname=wheel mode=0755\n')) as command:
                resolve(request)
                self.assertEqual(command.call_args.kwargs['env']['LD_LIBRARY_PATH'], directory)
                self.assertEqual(os.environ['LD_LIBRARY_PATH'], '/inherited')

    def test_missing_native_mtree_library_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            request = self.request()
            request['mtree_runtime_libraries'] = [str(Path(directory) / 'missing.so')]
            with patch('archive_policy.accounts', return_value={'root': 0, 'wheel': 0}), patch('archive_policy.subprocess.run') as command:
                with self.assertRaisesRegex(ValueError, 'missing mtree runtime'):
                    resolve(request)
                command.assert_not_called()

if __name__=='__main__':unittest.main()
