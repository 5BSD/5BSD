#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Reject invalid manifest graphs even when on-disk links share an inode."""
import json
import os
from pathlib import Path
import tempfile
import unittest
import stage_verify


class HardlinkStage(unittest.TestCase):
    def test_valid_and_invalid_graphs(self):
        regular = dict(type='file', owner='root', group='wheel', mode='444')
        chain = {'/z':regular, '/a':dict(regular,type='hardlink',link='/b'),
                 '/b':dict(regular,type='hardlink',link='/z')}
        self.assertEqual(stage_verify.hardlink_roots(chain), {'/z':'/z','/b':'/z','/a':'/z'})
        for replacement, error in ((dict(type='hardlink',link='/a'), 'cycle'),
                (dict(type='hardlink',link='/missing'), 'source missing'),
                (dict(type='symlink',link='z'), 'not regular'),
                (dict(regular,type='hardlink',link='/z',mode='600'), 'metadata differs')):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError,error):
                stage_verify.hardlink_roots(dict(chain, **{'/b':replacement}))

    def check_stage(self, *, split=False, cycle=False):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);workspace=root/'workspace';binary=workspace/'bazel-bin'
            tree=binary/'native_stage.root';tree.mkdir(parents=True)
            (tree/'z').write_bytes(b'payload\n');(binary/'source').write_bytes(b'payload\n')
            os.link(tree/'z',tree/'b')
            if split:(tree/'a').write_bytes(b'payload\n')
            else:os.link(tree/'b',tree/'a')
            meta='. type=dir uname=root gname=wheel mode=0755\n'
            sha=stage_verify.digest(tree/'z')
            for name in ('a','b','z'):
                meta+='./'+name+' type=file uname=root gname=wheel mode=0444 sha256='+sha+' size=8\n'
            (binary/'native_stage.METALOG').write_text(meta)
            reference=root/'reference';reference.mkdir();(reference/'METALOG').write_text(meta)
            regular=dict(owner='root',group='wheel',mode='444',type='file',destination='/z',source='bazel-bin/source')
            entries=[regular,dict(regular,type='hardlink',destination='/a',link='/b'),
                     dict(regular,type='hardlink',destination='/b',link='/a' if cycle else '/z')]
            (binary/'sample_install_manifest.json').write_text(json.dumps(dict(files=entries)))
            policy=root/'policy.json';policy.write_text(json.dumps(dict(status='reconciled',reference=str(reference),payloads={e['destination']:{} for e in entries})))
            directories=root/'directories.json';directories.write_text(json.dumps(dict(status='reconciled',reference=str(reference),directories={'/':dict(type='dir',uname='root',gname='wheel',mode=0o755,tags=[])},input_sha256={str(policy):stage_verify.digest(policy)})))
            return stage_verify.verify(workspace,directories,component_plans=[policy],manifest_names=['sample'])

    def test_actual_chain(self):
        self.assertEqual(self.check_stage()['hardlinks'],2)

    def test_same_bytes_different_inode(self):
        with self.assertRaisesRegex(ValueError,'hardlink inode differs'):
            self.check_stage(split=True)

    def test_cycle_with_same_inode(self):
        with self.assertRaisesRegex(ValueError,'hardlink cycle'):
            self.check_stage(cycle=True)


if __name__=='__main__':
    unittest.main()
