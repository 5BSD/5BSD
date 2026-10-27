# SPDX-License-Identifier: BSD-2-Clause
"""Real UFS image alignment and fsck; no mounts, device creation or boot."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
parser=argparse.ArgumentParser()
for name in ('makefs','fsck','dumpfs'):
    parser.add_argument('--'+name,required=True,type=Path)
args, remaining=parser.parse_known_args()
spec=importlib.util.spec_from_file_location('artifacts',ROOT/'tools/build/capimage/verity_artifacts.py')
artifacts=importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


class Geometry(unittest.TestCase):
    def run_tool(self, tool, *arguments):
        executable=getattr(args,tool)
        self.assertTrue(executable.is_file())
        result=subprocess.run([str(executable),*map(str,arguments)],
            stdin=subprocess.DEVNULL,capture_output=True,text=True,
            env=dict(os.environ,LC_ALL='C'),timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        return result.stdout+result.stderr

    def filesystem_geometry(self, image):
        output=self.run_tool('dumpfs','-s',image)
        self.assertIn('(UFS2)',output)
        values=[]
        for name in ('bsize','fsize','frag','fsbtodb'):
            match=re.search(r'\b'+name+r'\s+(\d+)',output)
            self.assertIsNotNone(match,output)
            values.append(int(match.group(1)))
        return tuple(values)

    def test_all_verification_block_sizes_preserve_filesystem_geometry(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'source';root.mkdir()
            (root/'payload').write_bytes(bytes(range(256))*513)
            (root/'subdir').mkdir()
            (root/'subdir/link').symlink_to('../payload')
            os.link(root/'payload',root/'alias')
            baseline=Path(directory)/'baseline.ufs'
            self.run_tool('makefs','-t','ffs','-o','version=2',baseline,root)
            expected_geometry=self.filesystem_geometry(baseline)
            for exponent in range(9,17):
                block=1<<exponent
                with self.subTest(block_size=block):
                    folder=Path(directory)/str(block);folder.mkdir()
                    image=folder/'system.ufs'
                    policy=dict(format=1,block_size=block,salt_hex='aabb')
                    self.run_tool('makefs','-t','ffs','-o','version=2',
                                  *artifacts.makefs_options(policy),image,root)
                    self.assertEqual(image.stat().st_size%block,0)
                    self.assertEqual(self.filesystem_geometry(image),expected_geometry)
                    before=artifacts.digest(image)
                    checked=self.run_tool('fsck','-f','-n',image)
                    self.assertIn('Phase 5',checked)
                    self.assertEqual(artifacts.digest(image),before)
                    receipt=artifacts.build(folder,policy,before,image.stat().st_size)
                    artifacts.verify(folder,receipt,policy,before,image.stat().st_size)
                    self.assertEqual(artifacts.digest(image),before)


if __name__=='__main__': unittest.main(argv=[__file__,*remaining])
