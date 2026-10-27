# SPDX-License-Identifier: BSD-2-Clause
"""Adversarial host collector tests; synthetic bytes, not UFS verification."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from export_image import collect, file_hash


class Collection(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name); self.vm = self.work / 'vm'; self.vm.mkdir()
        self.image = b'test image'.ljust(512, b'\0')
        self.raw = self.vm / 'output.img'
        with self.raw.open('wb') as stream:
            stream.write(self.image); stream.truncate(16 * 1048576)
        self.record = dict(result='PASS', scope='private-image-export', image_bytes=len(self.image),
            image_sha256=hashlib.sha256(self.image).hexdigest(), output_bytes=self.raw.stat().st_size,
            output_sha256=file_hash(self.raw), generation_authenticated=False, activation_authorized=False)
        self.result = dict(result='PASS', qemu_exit=0, forced_termination=False,
            input_disk_readonly=True, input_disk_sha256='a' * 64, input_disk_final_sha256='a' * 64,
            output_disk_mib=16, output_disk_sha256=self.record['output_sha256'])
        self.save()

    def save(self):
        (self.vm / 'result.json').write_text(json.dumps(self.result))
        (self.vm / 'serial.log').write_text('IMAGE_EXPORT_RESULT ' + json.dumps(self.record) + '\n')

    def layout_output(self):
        from export_layout import create
        source = self.work / 'source'; source.mkdir()
        report = dict(format=1, scope='trusted-builder-storage-images', result='PASS',
            generation_authenticated=False, activation_authorized=False,
            seeds_installed=False, attachments_constructed=False,
            source_observation_sha256='1'*64, images=[])
        for name in ('base', 'seed-1'):
            folder = source / name; folder.mkdir()
            image = (name + ' image').encode(); manifest = (name + ' manifest').encode()
            (folder / 'system.ufs').write_bytes(image)
            (folder / 'filesystem.mtree').write_bytes(manifest)
            receipt = dict(scope='trusted-builder-partition-image', result='PASS',
                source_observation_sha256='1'*64, inputs_authenticated=False,
                generation_authenticated=False, activation_authorized=False,
                image_bytes=len(image), image_sha256=hashlib.sha256(image).hexdigest(),
                manifest_sha256=hashlib.sha256(manifest).hexdigest())
            (folder / 'receipt.json').write_text(json.dumps(receipt))
            report['images'].append(dict(directory=name, receipt=receipt))
        (source / 'receipt.json').write_text(json.dumps(report))
        archive = self.work / 'source.tar'
        transported = create(source, archive)
        with self.raw.open('wb') as stream:
            stream.write(archive.read_bytes()); stream.truncate(16 * 1048576)
        self.record = dict(result='PASS', scope='private-layout-export',
            layout_bytes=transported['layout_bytes'], layout_sha256=transported['layout_sha256'],
            output_bytes=self.raw.stat().st_size, output_sha256=file_hash(self.raw),
            generation_authenticated=False, activation_authorized=False)
        self.result['output_disk_sha256'] = self.record['output_sha256']
        self.save()
        return source

    def test_layout_collects_all_partitions(self):
        source = self.layout_output()
        report = collect(self.work)
        self.assertEqual(report['scope'], 'post-shutdown-layout-export')
        self.assertFalse(report['artifacts']['selected_inputs_verified'])
        for path in source.rglob('*'):
            if path.is_file():
                self.assertEqual(path.read_bytes(), (self.work / 'layout' / path.relative_to(source)).read_bytes())
        self.assertTrue((self.work / 'layout.json').is_file())

    def test_layout_forced_shutdown_refused(self):
        self.layout_output(); self.result['forced_termination'] = True; self.save()
        with self.assertRaises(ValueError): collect(self.work)
        self.assertFalse((self.work / 'layout').exists())

    def test_layout_changed_input_refused(self):
        self.layout_output(); self.result['input_disk_final_sha256'] = 'b'*64; self.save()
        with self.assertRaises(ValueError): collect(self.work)
        self.assertFalse((self.work / 'layout').exists())

    def test_layout_changed_output_refused(self):
        self.layout_output()
        with self.raw.open('r+b') as stream: stream.write(b'changed')
        with self.assertRaises(ValueError): collect(self.work)
        self.assertFalse((self.work / 'layout').exists())

    def test_exact_image_and_private_output(self):
        report = collect(self.work)
        self.assertEqual((self.work / 'image.ufs').read_bytes(), self.image)
        self.assertEqual((self.work / 'image.ufs').stat().st_mode & 0o777, 0o600)
        self.assertFalse(report['generation_authenticated'])
        self.assertFalse(report['activation_authorized'])

    def test_missing_input_binding(self):
        del self.result['input_disk_sha256']; del self.result['input_disk_final_sha256']; self.save()
        with self.assertRaises(ValueError): collect(self.work)
        self.assertFalse((self.work / 'image.json').exists())

    def test_failed_vm(self):
        self.result['result'] = 'FAIL'; self.save()
        with self.assertRaises(ValueError): collect(self.work)

    def test_changed_raw_output(self):
        with self.raw.open('r+b') as stream: stream.write(b'changed')
        with self.assertRaises(ValueError): collect(self.work)
        self.assertFalse((self.work / 'image.ufs').exists())

    def test_wrong_image_digest(self):
        self.record['image_sha256'] = 'b' * 64; self.save()
        with self.assertRaises(ValueError): collect(self.work)
        self.assertFalse((self.work / 'image.json').exists())

    def test_duplicate_export_record(self):
        serial = self.vm / 'serial.log'; serial.write_text(serial.read_text() * 2)
        with self.assertRaises(ValueError): collect(self.work)

    def test_existing_image_preserved(self):
        target = self.work / 'image.ufs'; target.write_bytes(b'previous evidence')
        with self.assertRaises(FileExistsError): collect(self.work)
        self.assertEqual(target.read_bytes(), b'previous evidence')


if __name__ == '__main__':
    unittest.main()
