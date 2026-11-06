# SPDX-License-Identifier: BSD-2-Clause
"""Execution-path identity survives symlink repositories and same-basename files."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from payload_inventory import inventory

class PayloadInventory(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        old = Path.cwd()
        self.addCleanup(os.chdir, old)
        os.chdir(self.temp.name)
        Path("source").mkdir()
        Path("source/LICENSE").write_bytes(b"source license\n")
        Path("external/repository").mkdir(parents=True)
        Path("external/repository/LICENSE").symlink_to("../../source/LICENSE")
        Path("LICENSE").write_bytes(b"different license\n")

    def test_declared_alias_identity_and_same_basename_are_preserved(self):
        result = inventory(["external/repository/LICENSE", "LICENSE"])
        self.assertEqual(set(result["files"]), {"external/repository/LICENSE", "LICENSE"})
        self.assertEqual(result["files"]["external/repository/LICENSE"]["sha256"], hashlib.sha256(b"source license\n").hexdigest())
        self.assertNotEqual(result["files"]["LICENSE"]["sha256"], result["files"]["external/repository/LICENSE"]["sha256"])
        self.assertNotIn("source/LICENSE", result["files"])

    def test_no_duplicate_empty_directory_or_unsafe_path_fallback(self):
        for paths in ([], ["LICENSE", "LICENSE"], ["source"], ["/LICENSE"], ["../LICENSE"], ["source/../LICENSE"], ["./LICENSE"]):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                inventory(paths)
        with self.assertRaisesRegex(ValueError, "regular declared payload"):
            inventory(["undeclared-missing"])

if __name__ == "__main__":
    unittest.main()
