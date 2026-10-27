#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Generated install inputs must be independent of old object-directory files."""
from pathlib import Path
import tempfile
import unittest
import install_sources


class InstallationSources(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.source = root / 'src'; self.source.mkdir()
        self.objects = root / 'obj'; self.objects.mkdir()
        self.inputs = {}
        self.generator = {'output': 'generated.conf', 'script': 'generate.sh'}
        self.catalogue = {'name': 'locale.cat', 'sources': []}

    def resolve(self, name):
        return install_sources.identity(name, self.source, self.objects,
            [self.source, self.objects], {'generated.conf': self.generator},
            {'locale.cat': self.catalogue}, self.inputs)

    def test_declared_generator_ignores_stale_object(self):
        (self.objects / 'generated.conf').write_text('stale')
        for name in ('generated.conf', str(self.objects / 'generated.conf')):
            self.assertEqual(self.resolve(name),
                             {'generated_output': 'generated.conf', 'generator': self.generator})
        self.assertFalse(self.inputs)

    def test_declared_catalogue_ignores_stale_object(self):
        (self.objects / 'locale.cat').write_text('stale')
        for name in ('locale.cat', str(self.objects / 'locale.cat')):
            self.assertEqual(self.resolve(name),
                             {'catalogue_output': 'locale.cat', 'catalogue': self.catalogue})
        self.assertFalse(self.inputs)

    def test_undeclared_object_rejected(self):
        (self.objects / 'other').write_text('unmodeled')
        with self.assertRaisesRegex(ValueError, 'outside maintained source'):
            self.resolve('other')

    def test_other_absolute_directory_is_not_generated(self):
        outside = self.source.parent / 'generated.conf'; outside.write_text('wrong origin')
        with self.assertRaisesRegex(ValueError, 'outside maintained source'):
            self.resolve(str(outside))

    def test_source_file_is_hash_bound(self):
        source = self.source / 'ordinary'; source.write_text('configured')
        selected = self.resolve('ordinary')
        self.assertEqual(selected['source_origin'], str(source))
        self.assertEqual(self.inputs, {str(source): selected['source_sha256']})

    def test_source_symlink_cannot_escape(self):
        outside = self.objects / 'ordinary'; outside.write_text('outside')
        (self.source / 'ordinary').symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'outside maintained source'):
            self.resolve('ordinary')


if __name__ == '__main__':
    unittest.main()
