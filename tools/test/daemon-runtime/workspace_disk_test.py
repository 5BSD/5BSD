# SPDX-License-Identifier: BSD-2-Clause
import importlib.util
from pathlib import Path
import tempfile
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('workspace_disk',Path(__file__).with_name('workspace_disk.py'))
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)


class Workspace(unittest.TestCase):
    def test_explicit_topology_and_bounds(self):
        self.assertEqual(w.requirement(0,False,0,512,1024),0)
        self.assertEqual(w.requirement(32768,True,8192,512,1024),43008*w.MIB)
        for args in ((16,False,8192,512,1024),(16,True,0,512,1024),
                     (15,True,8192,512,1024),(65537,True,8192,512,1024),
                     (True,True,8192,512,1024),(16,True,8192,512,-1)):
            with self.subTest(args=args),self.assertRaises(ValueError):w.requirement(*args)

    def test_host_capacity_is_checked_before_creation(self):
        with tempfile.TemporaryDirectory() as temp:
            work=Path(temp)/'new'/'work'
            with patch.object(w.os,'statvfs',return_value=SimpleNamespace(f_bavail=10,f_frsize=4096)):
                with self.assertRaisesRegex(ValueError,'insufficient'):w.check_space(work,40961)
                self.assertEqual(w.check_space(work,40960)['available_bytes'],40960)
            self.assertFalse(work.parent.exists())

    def test_runner_rejects_workspace_without_required_disks(self):
        runner=Path(__file__).with_name('run-vm.py')
        with tempfile.TemporaryDirectory() as temp:
            work=Path(temp)/'never-created'
            result=subprocess.run([sys.executable,'-B',str(runner),
                '--root','/nonexistent','--objtop','/usr/obj/usr/src/amd64.amd64',
                '--work',str(work),'--qemu','/nonexistent','--qemu-data','/nonexistent',
                '--workspace-disk-mib','32768','--host-max-rss-mib','4096'],capture_output=True,text=True)
            self.assertEqual(result.returncode,2)
            self.assertIn('workspace disk requires',result.stderr)
            self.assertFalse(work.exists())

    def test_disk_is_private_zeroed_and_exclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            disk=Path(temp)/'workspace.img';w.create(disk,16)
            self.assertEqual(disk.stat().st_size,16*w.MIB)
            self.assertEqual(disk.stat().st_mode&0o777,0o600)
            with disk.open('rb') as stream:
                self.assertEqual(stream.read(4096),bytes(4096))
                stream.seek(-4096,2);self.assertEqual(stream.read(),bytes(4096))
            with self.assertRaises(FileExistsError):w.create(disk,16)
            link=Path(temp)/'link';link.symlink_to(disk)
            with self.assertRaises(FileExistsError):w.create(link,16)


if __name__=='__main__':unittest.main()
