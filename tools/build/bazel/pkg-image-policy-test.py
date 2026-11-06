# SPDX-License-Identifier: BSD-2-Clause
"""Reject unsafe image paths and unsupported boot policy without running tools."""
import copy
import json
import os
from pathlib import Path
import unittest
from pkg_image import destination, policy_check

class ImagePolicy(unittest.TestCase):
    def setUp(self):
        root=Path(os.environ["TEST_SRCDIR"])/os.environ["TEST_WORKSPACE"]
        self.policy=json.loads((root/"tools/build/bazel/tests/system_pkg_boot/image.json").read_text())

    def test_explicit_policy_and_paths(self):
        policy_check(self.policy)
        for path in ("/", "/boot/kernel", "/var/db/pkg/local.sqlite"):
            self.assertEqual(destination(path),path)
        for path in ("relative", "//boot", "/boot/../etc", "/boot/./kernel", "/a b", "/a\nextra", "/nul\0"):
            with self.subTest(path=path),self.assertRaises(ValueError):destination(path)

    def test_no_silent_filesystem_or_boot_fallback(self):
        for key,value in (("filesystem","ufs"),("boot_mode","uefi"),("format",True),("size_bytes",0),("epoch",-1)):
            policy=copy.deepcopy(self.policy);policy[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):policy_check(policy)
        policy=copy.deepcopy(self.policy);policy["bootcode"]["ignored"]="/boot/loader.efi"
        with self.assertRaisesRegex(ValueError,"BIOS pmbr"):policy_check(policy)

if __name__=="__main__":unittest.main()
