#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from package_index import packages


class IndexTest(unittest.TestCase):
    def test_index_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "current.pkg"
            payload.write_bytes(b"current")
            (root / "stale.pkg").write_bytes(b"stale")
            record = dict(name=payload.name, sha256=hashlib.sha256(payload.read_bytes()).hexdigest())
            def index(entries):
                (root / "index.json").write_text(json.dumps(dict(format=1, packages=entries)))
            index([record])
            self.assertEqual(packages(root), [payload])
            index([record, record])
            with self.assertRaises(ValueError):
                packages(root)
            index([dict(record, name="../escape.pkg")])
            with self.assertRaises(ValueError):
                packages(root)
            index([record])
            payload.write_bytes(b"modified")
            with self.assertRaises(ValueError):
                packages(root)
            payload.unlink()
            with self.assertRaises(ValueError):
                packages(root)


if __name__ == "__main__":
    unittest.main()
