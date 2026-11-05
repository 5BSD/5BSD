# SPDX-License-Identifier: BSD-2-Clause
import json
import os
from pathlib import Path
import tarfile
import unittest


class GeneratedZoneTreeTests(unittest.TestCase):
    def test_bazel_expands_and_packages_all_generated_files(self):
        root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
        base = root / 'tools/build/bazel/tests/zoneinfo'
        metadata = json.loads((base / 'fixture_archive.json').read_text())
        records = {r['destination']: r for r in metadata['records']}
        files = {p for p, r in records.items() if r['type'] == 'file'}
        self.assertEqual(files, {'/usr/share/zoneinfo/Foundry/' + n for n in ['One', 'Two', 'Three']})
        self.assertIn('/usr/share/zoneinfo/Compatibility/Empty', records)
        with tarfile.open(base / 'fixture_archive.tar') as archive:
            payloads = {}
            for path in files:
                member = archive.getmember(path.lstrip('/'))
                self.assertTrue(member.isfile())
                self.assertEqual(member.mode, 0o444)
                payloads[path] = archive.extractfile(member).read()
                self.assertTrue(payloads[path].startswith(b'TZif'))
            self.assertEqual(payloads['/usr/share/zoneinfo/Foundry/One'],
                             payloads['/usr/share/zoneinfo/Foundry/Three'])
            self.assertTrue(archive.getmember('usr/share/zoneinfo/Compatibility/Empty').isdir())


if __name__ == '__main__':
    unittest.main()
