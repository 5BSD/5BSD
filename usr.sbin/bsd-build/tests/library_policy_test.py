# SPDX-License-Identifier: BSD-2-Clause
import copy
import hashlib
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

helper = os.environ.get('BSD_BUILD_CONSTRUCTION_HELPER') or str(Path(__file__).resolve().parents[3] / 'tools/build/capimage/construction.py')
spec = importlib.util.spec_from_file_location('construction', helper)
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


class LibraryPolicy(unittest.TestCase):
    def setUp(self):
        self.observed = {p:dict(type='directory',uid=0,gid=0,mode=0o755,flags_set=0)
                         for p in ('/', '/usr', '/usr/lib', '/sbin', '/etc')}
        self.observed['/sbin/ldconfig'] = dict(type='file',sha256='a'*64,mode=0o555)
        entries = copy.deepcopy(self.observed); del entries['/']
        self.inventory = {'packages':[dict(name='runtime',archive_sha256='b'*64,entries=entries,directories={})]}
        self.policy = dict(format=1,program='/sbin/ldconfig',directories=['/usr/lib'],output='/etc/hints')

    def prepare(self):
        return c.libraries.prepare(self.inventory,self.observed,self.policy,c.pkg,c.digest)

    def test_bound_action(self):
        p=self.prepare();a=p['actions'][0]
        self.assertEqual(a['argv'],['/sbin/ldconfig','-elf','-S','-f','/etc/hints','/usr/lib'])
        self.assertEqual(a['executable_payload']['archive_sha256'],'b'*64)
        self.assertFalse(p['inputs_authenticated']);self.assertFalse(p['runtime_storage_authorized'])
        c.check_action_inputs(a,self.observed)
        self.observed['/usr']['mode']=0o777
        with self.assertRaisesRegex(ValueError,'directory changed'):c.check_action_inputs(a,self.observed)

    def test_invalid_paths(self):
        for value in ['/usr/../lib','usr/lib','/usr//lib','/usr/lib:else','/usr/lib/','/usr/lib\n']:
            with self.subTest(value=value):
                self.policy['directories']=[value]
                with self.assertRaises(ValueError):self.prepare()

    def test_invalid_policy(self):
        for directories in ([], ['/usr/lib','/usr/lib'], '/usr/lib'):
            with self.subTest(directories=directories):
                self.policy['directories']=directories
                with self.assertRaises(ValueError):self.prepare()

    def test_unowned_aliased_and_mutable_directories(self):
        for key,value in [('type','symlink'),('uid',1),('mode',0o775)]:
            before=copy.deepcopy(self.observed)
            self.observed['/usr'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.prepare()
            self.observed=before
        del self.inventory['packages'][0]['entries']['/usr/lib']
        with self.assertRaisesRegex(ValueError,'package-declared'):self.prepare()

    def test_generator_and_output(self):
        self.observed['/sbin/ldconfig']['sha256']='c'*64
        with self.assertRaises(ValueError):self.prepare()
        self.observed['/sbin/ldconfig']['sha256']='a'*64
        self.observed['/etc/hints']=dict(type='file')
        with self.assertRaisesRegex(ValueError,'must be new'):self.prepare()

    def test_shipped_protected_policy(self):
        self.policy = json.loads(Path(c.libraries.__file__).with_name('library-policy.json').read_text())
        self.observed['/boot'] = dict(type='directory',uid=0,gid=0,mode=0o755,flags_set=0)
        self.inventory['packages'][0]['entries']['/boot'] = copy.deepcopy(self.observed['/boot'])
        self.observed['/lib'] = dict(type='directory',uid=0,gid=0,mode=0o755,flags_set=0)
        self.inventory['packages'][0]['entries']['/lib'] = copy.deepcopy(self.observed['/lib'])
        action = self.prepare()['actions'][0]
        self.assertEqual(action['argv'], ['/sbin/ldconfig', '-elf', '-S', '-f',
            '/boot/ld-elf.so.hints', '/lib', '/usr/lib'])
        tool = os.environ.get('BSD_BUILD_LDCONFIG')
        if tool:
            with tempfile.TemporaryDirectory() as work:
                output = Path(work) / 'hints'
                subprocess.run([tool, '-elf', '-S', '-f', str(output), *self.policy['directories']], check=True)
                self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(),
                    action['planned_hashes'][self.policy['output']])

    def test_real_generator_content(self):
        tool=os.environ.get('BSD_BUILD_LDCONFIG')
        if not tool:self.skipTest('explicit built ldconfig required')
        a=self.prepare()['actions'][0]
        with tempfile.TemporaryDirectory() as work:
            output=Path(work)/'hints'
            subprocess.run([tool,'-elf','-S','-f',str(output),'/usr/lib'],check=True)
            self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(),a['planned_hashes']['/etc/hints'])

if __name__=='__main__':unittest.main()
