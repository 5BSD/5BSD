# SPDX-License-Identifier: BSD-2-Clause
"""Inspect actual configured install manifests and archives; execute no payload."""
import argparse
import json
from pathlib import Path, PurePosixPath
import tarfile
import unittest

p = argparse.ArgumentParser()
p.add_argument("--manifest", type=Path, required=True)
p.add_argument("--archive", type=Path, required=True)
p.add_argument("--payload", type=Path, required=True)
p.add_argument("--directory", required=True)
a = p.parse_args()

class InstallationAlias(unittest.TestCase):
    def test_manifest(self):
        records = json.loads(a.manifest.read_text())["files"]
        self.assertEqual(len(records), 2)
        by_path = {r["destination"]: r for r in records}
        self.assertEqual(set(by_path), {a.directory + "/driver.ko", a.directory + "/alias.ko"})
        for r in records:
            self.assertEqual((r["owner"], r["group"], r["tags"]), ("root", "wheel", ["package=kernel"]))
        module, alias = by_path[a.directory + "/driver.ko"], by_path[a.directory + "/alias.ko"]
        self.assertEqual((module["type"], module["mode"]), ("file", "0444"))
        self.assertEqual((alias["type"], alias["mode"], alias["link"]), ("symlink", "0755", "driver.ko"))

    def test_archive_payload(self):
        with tarfile.open(a.archive) as tar:
            entries = {str(PurePosixPath(r.name)): r for r in tar.getmembers()}
            file = entries[a.directory.lstrip("/") + "/driver.ko"]
            self.assertTrue(file.isfile())
            self.assertEqual((file.uid, file.gid, file.mode, file.mtime), (0, 0, 0o444, 42))
            self.assertEqual(tar.extractfile(file).read(), a.payload.read_bytes())

    def test_archive_alias(self):
        with tarfile.open(a.archive) as tar:
            entries = {str(PurePosixPath(r.name)): r for r in tar.getmembers()}
            link = entries[a.directory.lstrip("/") + "/alias.ko"]
            self.assertTrue(link.issym())
            self.assertEqual((link.uid, link.gid, link.mode, link.mtime, link.linkname), (0, 0, 0o755, 42, "driver.ko"))
            resolved = PurePosixPath(link.name).parent / link.linkname
            self.assertTrue(entries[str(resolved)].isfile())

if __name__ == "__main__":
    unittest.main(argv=[__file__])
