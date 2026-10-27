# SPDX-License-Identifier: BSD-2-Clause
"""Real tar/collector checks with synthetic payloads, not boot qualification."""
import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import export_bundle as bundle
import export_image


class Bundle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.image = self.root / 'input.ufs'; self.image.write_bytes(b'image fixture')
        self.boot = self.root / 'boot.tar'; self.boot.write_bytes(b'opaque boot transport')
        self.receipt = dict(scope='trusted-builder-filesystem-image', result='PASS',
            generation_authenticated=False, activation_authorized=False,
            image_bytes=self.image.stat().st_size, image_sha256=bundle.digest(self.image),
            source_observation_sha256='a' * 64,
            boot_archive=dict(scope='generation-boot-transport', result='PASS',
                generation_authenticated=False, activation_authorized=False,
                metadata_reconstruction_required=True, source_observation_sha256='a' * 64,
                archive_bytes=self.boot.stat().st_size, archive_sha256=bundle.digest(self.boot)))
        self.archive = self.root / 'bundle.tar'
        self.record = bundle.create(self.image, self.boot, self.receipt, self.archive)

    def test_collect_exact_private_artifacts(self):
        target = self.root / 'collected'
        report = bundle.collect(self.archive, target)
        self.assertEqual(report['source_observation_sha256'], 'a' * 64)
        self.assertEqual((target / 'image.ufs').read_bytes(), self.image.read_bytes())
        self.assertEqual((target / 'boot.tar').read_bytes(), self.boot.read_bytes())
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        self.assertEqual((target / 'image.ufs').stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError): bundle.collect(self.archive, target)

    def test_mismatched_binding_or_source(self):
        for field, value in [('source_observation_sha256', 'b' * 64), ('result', 'FAIL'),
                             ('archive_sha256', 'c' * 64)]:
            receipt = copy.deepcopy(self.receipt); receipt['boot_archive'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bundle.create(self.image, self.boot, receipt, self.root / ('bad-' + field))
        self.boot.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            bundle.create(self.image, self.boot, self.receipt, self.root / 'changed.tar')

    def rewrite(self, mutate):
        with tarfile.open(self.archive) as source:
            records = [(m, source.extractfile(m).read()) for m in source.getmembers()]
        mutate(records)
        target = self.root / 'bad.tar'
        with tarfile.open(target, 'w') as out:
            for member, data in records:
                out.addfile(member, io.BytesIO(data))
        return target

    def test_corrupt_payload_refused_before_output(self):
        def change(records):
            member, data = records[0]; records[0] = (member, b'x' * len(data))
        bad = self.rewrite(change)
        with self.assertRaisesRegex(ValueError, 'digest'):
            bundle.collect(bad, self.root / 'collected')
        self.assertFalse((self.root / 'collected').exists())

    def test_unsafe_member_refused(self):
        for fault in ('traversal', 'symlink', 'duplicate'):
            def change(records):
                if fault == 'traversal': records[0][0].name = '../outside'
                elif fault == 'symlink':
                    records[0][0].type = tarfile.SYMTYPE; records[0][0].linkname = '/etc/passwd'
                else: records.append(records[0])
            bad = self.rewrite(change)
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                bundle.collect(bad, self.root / 'collected')
            self.assertFalse((self.root / 'collected').exists())

    def test_post_shutdown_collector(self):
        work = self.root / 'work'; vm = work / 'vm'; vm.mkdir(parents=True)
        raw = vm / 'output.img'
        with raw.open('wb') as out:
            out.write(self.archive.read_bytes()); out.truncate(16 * 1048576)
        record = dict(self.record, scope='private-bundle-export', output_bytes=16 * 1048576,
            output_sha256=bundle.digest(raw), generation_authenticated=False, activation_authorized=False)
        result = dict(result='PASS', qemu_exit=0, forced_termination=False,
            input_disk_readonly=True, input_disk_sha256='a' * 64, input_disk_final_sha256='a' * 64,
            output_disk_mib=16, output_disk_sha256=record['output_sha256'])
        (vm / 'result.json').write_text(json.dumps(result))
        (vm / 'serial.log').write_text('IMAGE_EXPORT_RESULT ' + json.dumps(record) + '\n')
        report = export_image.collect(work)
        self.assertEqual(report['scope'], 'post-shutdown-bundle-export')
        self.assertEqual((work / 'generation/image.ufs').read_bytes(), self.image.read_bytes())
        self.assertTrue((work / 'bundle.json').is_file())


if __name__ == '__main__':
    unittest.main()
