# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""The installed audit must retain all baseline objects and digest bindings."""
import copy
import hashlib
import unittest
from installed_audit import specification


class InstalledAudit(unittest.TestCase):
    def setUp(self):
        self.metalog = ('. type=dir uid=0 gid=0 mode=0755 flags=none time=0.0\n'
            './bin type=dir uid=0 gid=0 mode=0755 flags=none time=0.0\n'
            './bin/tool type=file uid=0 gid=17 mode=04555 flags=schg time=0.0\n'
            './alias type=link uid=0 gid=0 mode=0777 flags=none time=0.0 link=bin/tool\n').encode()
        self.report = dict(metalog_sha256=hashlib.sha256(self.metalog).hexdigest(),
            payload_sha256={'/bin/tool':'a'*64}, directories=2, files=2)

    def test_full_contract_keeps_content_and_permissions(self):
        result = specification(self.metalog, self.report).decode()
        self.assertEqual(len(result.splitlines()), 4)
        self.assertIn('uid=0 gid=17 mode=04555 flags=schg sha256digest='+'a'*64, result)
        self.assertIn('./alias type=link uid=0 gid=0 mode=0777 flags=none link=bin/tool',result)
        self.assertNotIn('time=',result)

    def test_empty_directory_contents_pruned_without_omitting_metadata(self):
        metalog=self.metalog+b'./empty type=dir uid=0 gid=0 mode=0700 flags=none time=0.0\n'
        report=copy.deepcopy(self.report)
        report.update(metalog_sha256=hashlib.sha256(metalog).hexdigest(),directories=3)
        result=specification(metalog,report).decode()
        self.assertIn('./empty type=dir uid=0 gid=0 mode=0700 flags=none ignore\n',result)
        self.assertNotIn('./bin type=dir uid=0 gid=0 mode=0755 flags=none ignore',result)

    def test_digest_and_coverage_mismatches_fail(self):
        for mutate in (
                lambda r:r.update(metalog_sha256='0'*64),
                lambda r:r['payload_sha256'].clear(),
                lambda r:r['payload_sha256'].update({'/unexplained':'b'*64}),
                lambda r:r['payload_sha256'].update({'/bin/tool':'invalid'}),
                lambda r:r.update(directories=1),
                lambda r:r.update(files=1)):
            report=copy.deepcopy(self.report);mutate(report)
            with self.subTest(report=report),self.assertRaises(ValueError):
                specification(self.metalog, report)

    def test_ambiguous_or_unsupported_records_fail(self):
        for changed in (
                self.metalog+self.metalog.splitlines(keepends=True)[0],
                self.metalog.replace(b'./bin/tool',b'./bin/../tool'),
                self.metalog.replace(b'./bin/tool',b'/bin/tool'),
                self.metalog.replace(b'./bin/tool',b'./absent/tool'),
                self.metalog.replace(b'uid=0 gid=17',b'uid=0 uid=17'),
                self.metalog.replace(b'type=file',b'type=socket'),
                self.metalog.replace(b'mode=04555',b'mode=09999'),
                self.metalog.replace(b'link=bin/tool',b'optional link=bin/tool')):
            report=copy.deepcopy(self.report)
            report['metalog_sha256']=hashlib.sha256(changed).hexdigest()
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                specification(changed,report)

if __name__=='__main__':unittest.main()
