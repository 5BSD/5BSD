#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""A self-consistent native stage must still match Make's config bytes."""
import hashlib,json,tempfile,unittest
from pathlib import Path
import stage_verify

def sha(data):return hashlib.sha256(data).hexdigest()

class ConfigurationParity(unittest.TestCase):
    def check(self,data,role="configuration"):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);workspace=root/'workspace';binary=workspace/'bazel-bin';tree=binary/'native_stage.root';(tree/'etc').mkdir(parents=True)
            reference=root/'reference';reference.mkdir()
            original=b'configured=yes\n';attrs='type=file uname=root gname=wheel mode=0600 tags=package=sample'+(',config' if role=='configuration' else '')
            dirs='. type=dir uname=root gname=wheel mode=0755\n./etc type=dir uname=root gname=wheel mode=0755\n'
            def record(payload):return './etc/sample.conf '+attrs+' sha256='+sha(payload)+' size='+str(len(payload))+'\n'
            (reference/'METALOG').write_text(dirs+record(original))
            (tree/'etc/sample.conf').write_bytes(data);(binary/'config.out').write_bytes(data)
            (binary/'native_stage.METALOG').write_text(dirs+record(data))
            (binary/'sample_install_manifest.json').write_text(json.dumps(dict(files=[dict(destination='/etc/sample.conf',type='file',source='bazel-bin/config.out')])))
            policy=root/'policy.json';policy.write_text(json.dumps(dict(status='reconciled',payloads={'/etc/sample.conf':{'role':role}},reference=str(reference),input_sha256={str(reference/'METALOG'):sha((reference/'METALOG').read_bytes())})))
            directories=root/'directories.json';directories.write_text(json.dumps(dict(status='reconciled',reference=str(reference),directories={name:dict(type='dir',uname='root',gname='wheel',mode=0o755,tags=[]) for name in ('/','/etc')},input_sha256={str(policy):sha(policy.read_bytes())})))
            return stage_verify.verify(workspace,directories,component_plans=[policy],manifest_names=['sample'])
    def test_matching_configuration(self):self.assertEqual(self.check(b'configured=yes\n')['status'],'passed')
    def test_self_consistent_wrong_configuration(self):
        with self.assertRaisesRegex(ValueError,'configuration bytes differ from Make reference'):
            self.check(b'configured=no\n')
    def test_matching_file_group(self):
        self.assertEqual(self.check(b'configured=yes\n',role='file')['status'],'passed')
    def test_wrong_file_group(self):
        with self.assertRaisesRegex(ValueError,'file-group bytes differ from Make reference'):
            self.check(b'configured=no\n',role='file')
if __name__=='__main__':unittest.main()
