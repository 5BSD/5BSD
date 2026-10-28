#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from bep_artifacts import snapshot

class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root/'output with space'
        self.source.write_bytes(b'original\n')
        self.file = dict(name='pkg/archive.tar', pathPrefix=['bazel-out','cfg','bin'], uri=self.source.as_uri(), digest=hashlib.sha256(self.source.read_bytes()).hexdigest(), length=str(self.source.stat().st_size))
        self.events = [dict(id=dict(targetCompleted=dict(label='//pkg:archive',configuration=dict(id='cfg'))),completed=dict(success=True,outputGroup=[dict(name='default',fileSets=[dict(id='root')])])),dict(id=dict(namedSet=dict(id='root')),namedSetOfFiles=dict(fileSets=[dict(id='leaf')])),dict(id=dict(namedSet=dict(id='leaf')),namedSetOfFiles=dict(files=[self.file]))]
    def run_snapshot(self):
        p=self.root/'events.json';p.write_text(''.join(json.dumps(e)+'\n' for e in self.events))
        return snapshot(p,self.root/'artifacts')
    def test_transitive_out_of_order_snapshot_survives_rebuild(self):
        result=self.run_snapshot();self.assertEqual(result['unique_files'],1)
        self.source.write_bytes(b'replacement')
        manifest=json.loads((self.root/'artifacts/manifest.json').read_text())
        output=manifest['targets'][0]['outputs'][0]
        self.assertEqual((self.root/'artifacts'/output['file']).read_bytes(),b'original\n')
        self.assertEqual(manifest['targets'][0]['target']['configuration']['id'],'cfg')
    def test_metadata_groups_and_private_storage(self):
        group=self.events[0]['completed']['outputGroup'][0]
        group['name']='metadata'
        self.run_snapshot()
        self.assertEqual((self.root/'artifacts').stat().st_mode & 0o777,0o700)
        self.assertEqual(next((self.root/'artifacts/files').iterdir()).stat().st_mode & 0o777,0o400)
    def test_empty_output_with_omitted_length(self):
        self.source.write_bytes(b'')
        self.file['digest']=hashlib.sha256(b'').hexdigest()
        del self.file['length']
        result=self.run_snapshot()
        self.assertEqual(result['bytes'],0)
        self.assertEqual(result['unique_files'],1)
    def test_nonempty_output_with_omitted_length_rejected(self):
        del self.file['length']
        with self.assertRaisesRegex(ValueError,'changed before'):self.run_snapshot()
    def test_missing_source_rejected(self):
        self.source.unlink()
        with self.assertRaisesRegex(ValueError,'regular output'):self.run_snapshot()
    def test_shared_files_deduplicated(self):
        second=json.loads(json.dumps(self.events[0]));second['id']['targetCompleted']['label']='//pkg:other';self.events.append(second)
        self.assertEqual(self.run_snapshot()['unique_files'],1)
    def test_stale_output_rejected(self):
        self.source.write_bytes(b'replacement')
        with self.assertRaisesRegex(ValueError,'changed before'):self.run_snapshot()
    def test_missing_file_set(self):
        self.events.pop()
        with self.assertRaisesRegex(ValueError,'missing BEP'):self.run_snapshot()
    def test_cycle(self):
        self.events[-1]['namedSetOfFiles']['fileSets']=[dict(id='root')]
        with self.assertRaisesRegex(ValueError,'cyclic'):self.run_snapshot()
    def test_remote_uri_rejected(self):
        self.file['uri']='bytestream://server/blob'
        with self.assertRaisesRegex(ValueError,'local file'):self.run_snapshot()
    def test_traversal_rejected(self):
        self.file['name']='../../escape'
        with self.assertRaisesRegex(ValueError,'unsafe'):self.run_snapshot()
    def test_directory_rejected(self):
        self.file['uri']=self.root.as_uri()
        with self.assertRaisesRegex(ValueError,'regular output'):self.run_snapshot()
    def test_missing_digest_rejected(self):
        del self.file['digest']
        with self.assertRaisesRegex(ValueError,'digest required'):self.run_snapshot()
    def test_aspect_not_conflated(self):
        extra=json.loads(json.dumps(self.events[0]));extra['id']['targetCompleted']['aspect']='//:aspect';extra['completed']['outputGroup'][0]['fileSets']=[dict(id='absent')];self.events.append(extra)
        self.assertEqual(self.run_snapshot()['unique_files'],1)
    def test_incomplete_group(self):
        self.events[0]['completed']['outputGroup'][0]['incomplete']=True
        with self.assertRaisesRegex(ValueError,'incomplete'):self.run_snapshot()

if __name__=='__main__':unittest.main()
