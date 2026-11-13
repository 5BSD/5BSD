# SPDX-License-Identifier: BSD-2-Clause
"""Adversarial logical-archive comparisons using real tar serialization."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--tar', type=Path, required=True)
parser.add_argument('--library', type=Path)
args, remaining = parser.parse_known_args()
sys.argv = [sys.argv[0], *remaining]
TAR = args.tar
if not TAR.is_absolute():
    TAR = Path(os.environ['TEST_SRCDIR']) / TAR
TAR = TAR.resolve(strict=True)
spec = importlib.util.spec_from_file_location('comparison', Path(__file__).with_name('package-archive-compare.py'))
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)
LIBRARY = args.library or comparison.archive_headers.LIBRARY
if not LIBRARY.is_absolute():
    LIBRARY = Path(os.environ['TEST_SRCDIR']) / LIBRARY
LIBRARY = LIBRARY.resolve(strict=True)


class PackageComparison(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def archive(self, name, *, data=b'original', epoch=0, mode=0o444,
                uid=0, manifest=None, duplicate=False, pax=None):
        # Deliberately hold declared sums constant: actual byte comparison must
        # detect a changed payload even if its metadata claims are misleading.
        if manifest is None:
            manifest = dict(name='fixture', files={'/payload': {'sum': 'unchanged claim', 'mtime': epoch}})
        body = json.dumps(manifest).encode()
        path = self.root / name
        with tarfile.open(path, 'w', format=tarfile.PAX_FORMAT) as archive:
            meta = tarfile.TarInfo('+MANIFEST')
            meta.size = len(body)
            archive.addfile(meta, io.BytesIO(body))
            entry = tarfile.TarInfo('/payload')
            entry.mode = mode
            entry.pax_headers = pax or {}
            entry.uid = uid
            entry.uname = 'root'
            entry.gname = 'wheel'
            entry.mtime = epoch
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
            if duplicate:
                archive.addfile(entry, io.BytesIO(data))
        return path

    def snapshot(self, name, **kwargs):
        return comparison.snapshot(self.archive(name, **kwargs), TAR, library=LIBRARY)

    def test_identical_logical_archives(self):
        a = self.snapshot('a.pkg')
        b = self.snapshot('b.pkg')
        self.assertEqual(comparison.compare(a, b), [])
        self.assertIn('data_sha256', a[1]['/payload'])

    def test_timestamps_remain_differences(self):
        a = self.snapshot('a.pkg')
        b = self.snapshot('b.pkg', epoch=2**33+7)
        differences = comparison.compare(a, b)
        self.assertTrue(any(r['section']=='entries' and r.get('field')=='mtime' for r in differences))
        self.assertEqual(a[1]['/payload']['data_sha256'], b[1]['/payload']['data_sha256'])

    def test_changed_bytes_with_unchanged_manifest(self):
        a = self.snapshot('a.pkg')
        b = self.snapshot('b.pkg', data=b'modified')
        self.assertEqual(a[0], b[0])
        self.assertTrue(any(r.get('field')=='data_sha256' for r in comparison.compare(a, b)))

    def test_numeric_ownership_and_modes_remain_differences(self):
        a = self.snapshot('a.pkg')
        b = self.snapshot('b.pkg', mode=0o666, uid=2**33+17)
        fields = {r.get('field') for r in comparison.compare(a, b) if r['section']=='entries'}
        self.assertTrue({'uid', 'mode'} <= fields)

    def test_duplicate_payload_and_manifest_coverage_refused(self):
        with self.assertRaisesRegex(ValueError, 'duplicate archive payload'):
            self.snapshot('duplicate.pkg', duplicate=True)
        with self.assertRaisesRegex(ValueError, 'coverage differs'):
            self.snapshot('coverage.pkg', manifest=dict(files={'/different': 'claim'}))

    def test_equivalent_hardlink_storage_choices_keep_raw_differences(self):
        paths = []
        for first, second in [('a', 'b'), ('b', 'a')]:
            path = self.root / (first + '.pkg')
            manifest = json.dumps(dict(files={'/a': 'same claim', '/b': 'same claim'})).encode()
            with tarfile.open(path, 'w', format=tarfile.PAX_FORMAT) as archive:
                meta = tarfile.TarInfo('+MANIFEST')
                meta.size = len(manifest)
                archive.addfile(meta, io.BytesIO(manifest))
                payload = tarfile.TarInfo('/' + first)
                payload.mode = 0o444
                payload.size = 7
                archive.addfile(payload, io.BytesIO(b'payload'))
                alias = tarfile.TarInfo('/' + second)
                alias.mode = 0o444
                alias.type = tarfile.LNKTYPE
                alias.linkname = '/' + first
                archive.addfile(alias)
            paths.append(path)
        snapshots = [comparison.snapshot(path, TAR, library=LIBRARY) for path in paths]
        self.assertTrue(comparison.compare(*snapshots))
        self.assertEqual(comparison.logical_compare(*snapshots), [])
        for snapshot in snapshots:
            self.assertEqual(comparison.logical_entries(snapshot[1])['/a']['hardlink_group'], ['/a', '/b'])

    def test_unmodeled_extended_metadata_refused(self):
        with self.assertRaisesRegex(ValueError, 'extended ACL/xattr metadata'):
            self.snapshot('xattrs.pkg', pax={'SCHILY.xattr.user.qualifier': 'must not disappear'})

    def test_decoded_path_collisions_refused(self):
        with self.assertRaisesRegex(ValueError, 'collision'):
            comparison.path_mapping({'/percent%25name': 'a', '/percent%name': 'b'})
        with self.assertRaisesRegex(ValueError, 'noncanonical'):
            comparison.path_mapping({'/etc/../payload': 'a'})
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            json.loads('{"name":"a","name":"b"}', object_pairs_hook=comparison.unique_object)


if __name__ == '__main__':
    unittest.main()
