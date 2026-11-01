#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from scratch_disk import policy, create, DiskMonitor, MIB


class ScratchDiskTest(unittest.TestCase):
    def test_independent_budget_required_and_legacy_zfs_preserved(self):
        with self.assertRaisesRegex(ValueError, 'requires an allocation budget'):
            policy(128, 0, 1024, Path('/tmp'))
        self.assertEqual(policy(128, 0, 1024, Path('/tmp'), require_budget=False)['max_allocated_bytes'], 0)

    def test_capacity_budget_and_reserve_bounds(self):
        for values in [(127, 1, 1024), (65537, 1, 1024), (128, 129, 1024), (128, -1, 1024), (128, 1, 255), (True, 1, 1024), (0, 1, 1024)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                policy(*values, Path('/tmp'))
        self.assertIsNone(policy(0, 0, 1024, Path('/tmp')))

    def test_insufficient_host_free_space_rejected(self):
        with patch('scratch_disk.shutil.disk_usage', return_value=shutil._ntuple_diskusage(1000*MIB, 500*MIB, 500*MIB)):
            with self.assertRaisesRegex(ValueError, 'exceeds current host free'):
                policy(128, 128, 1024, Path('/tmp'))

    def test_creation_outside_object_root_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'disk'
            with self.assertRaises(ValueError): create(path, 128*MIB)
            self.assertFalse(path.exists())

    def test_actual_file_budget_and_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'disk'
            path.write_bytes(os.urandom(8192))
            budget = {'logical_bytes':8192, 'max_allocated_bytes':1, 'minimum_host_free_bytes':0}
            monitor = DiskMonitor(path,budget,Path(tmp)/'resources')
            try:
                with self.assertRaisesRegex(ValueError, 'allocation budget'): monitor.observe(0)
            finally: report=monitor.close()
            self.assertGreater(report['max_observed_allocated_bytes'],1)
            self.assertEqual(len((Path(tmp)/'resources').read_text().splitlines()),1)
            monitor = DiskMonitor(path,{**budget,'max_allocated_bytes':0},Path(tmp)/'replacement')
            try:
                path.rename(Path(tmp)/'old'); path.write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'identity'): monitor.observe(0)
            finally: monitor.close()

    def test_free_reserve_exhaustion_is_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'disk';path.write_bytes(b'')
            monitor=DiskMonitor(path,{'logical_bytes':0,'max_allocated_bytes':0,'minimum_host_free_bytes':1},Path(tmp)/'resource')
            try:
                with patch('scratch_disk.shutil.disk_usage',return_value=shutil._ntuple_diskusage(1,1,0)):
                    with self.assertRaisesRegex(ValueError,'reserve exhausted'):monitor.observe(0)
            finally:monitor.close()

    def test_actual_cli_preflight_has_no_image_or_qemu_side_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);work=root/'absent'
            command=[sys.executable,'-B',str(Path(__file__).with_name('run-vm.py')),'--root',tmp,'--objtop',tmp,'--work',str(work),'--qemu',str(root/'absent-qemu'),'--qemu-data',tmp,'--scratch-disk-mib','128']
            bad=subprocess.run(command,capture_output=True,text=True,timeout=10)
            self.assertEqual(bad.returncode,2);self.assertIn('requires an allocation budget',bad.stderr);self.assertFalse(work.exists())
            valid=subprocess.run(command+['--scratch-host-max-allocated-mib','1'],capture_output=True,text=True,timeout=10)
            self.assertEqual(valid.returncode,2);self.assertIn('fixtures must use standard',valid.stderr);self.assertNotIn('requires --zfs',valid.stderr);self.assertFalse(work.exists())

if __name__=='__main__':unittest.main()
