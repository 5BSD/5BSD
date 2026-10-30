# SPDX-License-Identifier: BSD-2-Clause
"""Synthetic host evidence tests, not ZFS or VM qualification."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import collect_state_readback as subject


class Collector(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.disk = self.work / 'disk'; self.disk.write_bytes(b'synthetic populated disk')
        sha = subject.digest(self.disk)
        receipt = dict(pool_guid='1', parent_guid='2', dataset_guid='3', dataset='pool/state/var',
            scope='offline-new-state-dataset', result='PASS', source_observation_sha256='a'*64,
            initialization=dict(scope='offline-empty-state-initialization', result='PASS',
                source_observation_sha256='a'*64, initialized_observation_sha256='a'*64))
        document = dict(format=1, scope='initialized-state-vm-transport', output_disk_sha256=sha,
            report=dict(result='PASS', scope='ordinary-state-initialization', pool_exported=True,
                bindings=[dict(path='/var', receipt=receipt)]))
        self.selected = self.work / 'initialization.json'; self.selected.write_text(json.dumps(document))
        self.report = dict(bindings=1, contents_verified=True, runtime_qualified=False,
            allocation_sha256=subject.digest(self.selected), expected_disk_sha256=sha)
        self.result = dict(result='PASS', qemu_exit=0, forced_termination=False, input_disk_readonly=True,
            input_disk=str(self.disk), input_disk_sha256=sha, input_disk_final_sha256=sha)
        self.save()

    def save(self, copies=1):
        serial = self.work / 'serial.log'
        serial.write_text(('STATE_READBACK_PASS '+json.dumps(self.report)+'\n')*copies)
        self.result['serial_sha256'] = subject.digest(serial)
        (self.work / 'result.json').write_text(json.dumps(self.result))

    def collect(self): return subject.collect(self.work, self.selected, self.disk)

    def test_complete_binding(self):
        result = self.collect()
        self.assertEqual(result['result'], 'PASS')
        self.assertFalse(result['runtime_qualified'])
        self.assertFalse(result['generation_authenticated'])

    def test_forced_shutdown(self):
        self.result['forced_termination']=True; self.save()
        with self.assertRaises(ValueError): self.collect()

    def test_mismatched_selected_receipt(self):
        self.report['allocation_sha256']='b'*64; self.save()
        with self.assertRaises(ValueError): self.collect()

    def test_duplicate_report(self):
        self.save(2)
        with self.assertRaises(ValueError): self.collect()

    def test_changed_disk(self):
        self.disk.write_bytes(b'changed')
        with self.assertRaises(ValueError): self.collect()

    def test_changed_serial(self):
        with (self.work/'serial.log').open('a') as stream: stream.write('changed\n')
        with self.assertRaises(ValueError): self.collect()

    def test_no_content_verification(self):
        self.report['contents_verified']=False; self.save()
        with self.assertRaises(ValueError): self.collect()

    def test_wrong_dataset_count(self):
        self.report['bindings']=2; self.save()
        with self.assertRaises(ValueError): self.collect()

    def test_different_disk_path(self):
        self.result['input_disk']='/different'; self.save()
        with self.assertRaises(ValueError): self.collect()


if __name__ == '__main__': unittest.main()
