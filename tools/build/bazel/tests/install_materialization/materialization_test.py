# SPDX-License-Identifier: BSD-2-Clause
"""Verify physical links and canonical archive metadata as separate contracts."""
import argparse
import os
from pathlib import Path
import shlex
import tarfile
import unittest

parser=argparse.ArgumentParser()
for name in ["tree","metalog","archive","payload"]:
    parser.add_argument("--"+name,required=True)
args=parser.parse_args()
for name in ["tree","metalog","archive","payload"]:
    setattr(args,name,Path(os.environ["TEST_SRCDIR"])/getattr(args,name))


class MaterializationTest(unittest.TestCase):
    def test_actual_physical_links(self):
        # Bazel expands a directory artifact into per-file runfiles symlinks.
        # Follow a regular payload to its real output parent before inspecting
        # the materialized symlink itself, rather than the runfiles indirection.
        tree = (args.tree / "z").resolve(strict=True).parent
        self.assertEqual({p.name for p in tree.iterdir()},{"a","b","c","s","z"})
        for name in ["a","b","c"]:
            self.assertTrue((tree/name).samefile(tree/"z"))
        self.assertEqual(os.readlink(tree/"s"),"z")
        self.assertEqual((tree/"z").read_bytes(),args.payload.read_bytes())

    def test_canonical_inode_and_mode_policy(self):
        with tarfile.open(args.archive) as archive:
            members={v.name:v for v in archive.getmembers()}
            self.assertEqual(set(members),{".","a","b","c","s","z"})
            for name in ["a","b","c"]:
                self.assertTrue(members[name].islnk())
                self.assertEqual(members[name].linkname,"z")
            self.assertTrue(members["s"].issym())
            self.assertEqual(members["s"].linkname,"z")
            self.assertEqual(members["z"].mode,0o440)
            self.assertEqual(members["."].mode,0o750)
            self.assertTrue(all(v.uid==0 and v.gid==0 and v.mtime==42 for v in members.values()))
            self.assertEqual(archive.extractfile(members["z"]).read(),args.payload.read_bytes())
        records={}
        for line in args.metalog.read_text().splitlines():
            fields=shlex.split(line)
            records[fields[0]]=dict(v.split("=",1) for v in fields[1:])
        self.assertEqual(int(records["."]["mode"],8),0o750)
        for name in ["a","b","c","z"]:
            self.assertEqual(int(records["./"+name]["mode"],8),0o440)
            self.assertEqual(records["./"+name]["uname"],"root")
            self.assertEqual(records["./"+name]["gname"],"wheel")


if __name__=="__main__":
    unittest.main(argv=[__file__],verbosity=2)
