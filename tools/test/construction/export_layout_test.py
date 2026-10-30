#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Adversarial tests for split-image transport, not filesystem qualification."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import export_layout as transport


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work = self.root / 'layout'; self.work.mkdir()
        self.report = dict(format=1, scope='trusted-builder-storage-images', result='PASS',
            generation_authenticated=False, activation_authorized=False,
            seeds_installed=False, attachments_constructed=False,
            source_observation_sha256='1'*64, images=[])
        for index in range(3):
            name = 'base' if index == 0 else 'seed-' + str(index)
            folder = self.work / name; folder.mkdir()
            image = ('image' + str(index)).encode(); manifest = ('manifest' + str(index)).encode()
            (folder / 'system.ufs').write_bytes(image)
            (folder / 'filesystem.mtree').write_bytes(manifest)
            receipt = dict(scope='trusted-builder-partition-image', result='PASS',
                source_observation_sha256='1'*64, inputs_authenticated=False,
                generation_authenticated=False, activation_authorized=False,
                image_bytes=len(image), image_sha256=hashlib.sha256(image).hexdigest(),
                manifest_sha256=hashlib.sha256(manifest).hexdigest())
            if index == 0:
                (folder / 'boot.tar').write_bytes(b'boot')
                receipt['boot_archive'] = dict(result='PASS', archive_bytes=4,
                    archive_sha256=hashlib.sha256(b'boot').hexdigest())
            (folder / 'receipt.json').write_text(json.dumps(receipt))
            self.report['images'].append(dict(directory=name, receipt=receipt))
        (self.work / 'receipt.json').write_text(json.dumps(self.report))
        self.archive = self.root / 'layout.tar'

    def build(self):
        return transport.create(self.work, self.archive)

    def rewrite(self, transform):
        self.build()
        entries = []
        with tarfile.open(self.archive) as archive:
            for entry in archive:
                entries.append((entry.name, archive.extractfile(entry).read()))
        with tarfile.open(self.archive, 'w') as archive:
            for name, data in transform(entries):
                entry = tarfile.TarInfo(name); entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))

    def test_round_trip_verity_artifacts(self):
        combined=b'combined test artifact'
        descriptor=b'D'*384
        receipt=self.report['images'][0]['receipt']
        receipt['verity']=dict(image_bytes=len(combined),
            image_sha256=hashlib.sha256(combined).hexdigest(),
            descriptor_sha256=hashlib.sha256(descriptor).hexdigest())
        (self.work/'base/system.verity').write_bytes(combined)
        (self.work/'base/root.descriptor').write_bytes(descriptor)
        (self.work/'base/receipt.json').write_text(json.dumps(receipt))
        (self.work/'receipt.json').write_text(json.dumps(self.report))
        self.build()
        dest=self.root/'collected'
        transport.collect(self.archive,dest)
        self.assertEqual((dest/'base/system.verity').read_bytes(),combined)
        self.assertEqual((dest/'base/root.descriptor').read_bytes(),descriptor)
        self.report['images'][1]['receipt']['verity']=receipt['verity']
        with self.assertRaises(ValueError): transport.members(self.report)

    def test_round_trip_all_partitions(self):
        result = self.build()
        self.assertFalse(result['selected_inputs_verified'])
        dest = self.root / 'collected'
        report = transport.collect(self.archive, dest)
        self.assertFalse(report['generation_authenticated'])
        for source in self.work.rglob('*'):
            if source.is_file():
                self.assertEqual(source.read_bytes(), (dest / source.relative_to(self.work)).read_bytes())

    def test_missing_seed_refused_before_collection(self):
        self.rewrite(lambda entries: [e for e in entries if e[0] != 'seed-2/system.ufs'])
        dest = self.root / 'collected'
        with self.assertRaises(ValueError): transport.collect(self.archive, dest)
        self.assertFalse(dest.exists())

    def test_changed_image_refused(self):
        self.rewrite(lambda entries: [(n, b'broken' if n == 'base/system.ufs' else d) for n,d in entries])
        with self.assertRaises(ValueError): transport.collect(self.archive, self.root / 'collected')

    def test_extra_traversal_member_refused(self):
        self.rewrite(lambda entries: entries + [('../escape', b'x')])
        with self.assertRaises(ValueError): transport.collect(self.archive, self.root / 'collected')
        self.assertFalse((self.root / 'escape').exists())

    def test_duplicate_member_refused(self):
        self.rewrite(lambda entries: entries + [entries[1]])
        with self.assertRaises(ValueError): transport.collect(self.archive, self.root / 'collected')

    def test_symlink_partition_refused(self):
        (self.work / 'seed-1').rename(self.work / 'other')
        (self.work / 'seed-1').symlink_to('other')
        with self.assertRaises(ValueError): self.build()

    def test_existing_destination_preserved(self):
        self.build()
        dest = self.root / 'collected'; dest.mkdir(); (dest / 'keep').write_text('original')
        with self.assertRaises(FileExistsError): transport.collect(self.archive, dest)
        self.assertEqual((dest / 'keep').read_text(), 'original')

    def test_duplicate_json_key_refused(self):
        with self.assertRaises(ValueError): transport.decode(b'{"format":1,"format":1}')

    def test_receipt_path_not_used(self):
        self.report['images'][1]['directory'] = '../escape'
        (self.work / 'receipt.json').write_text(json.dumps(self.report))
        with self.assertRaises(ValueError): self.build()

    def test_embedded_receipt_mismatch_refused(self):
        (self.work / 'seed-1/receipt.json').write_text('{}')
        with self.assertRaises(ValueError): self.build()


if __name__ == '__main__':
    unittest.main()
