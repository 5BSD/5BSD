#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Verify PIC installation follows Make definition state, not truthy values."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('policy', Path(__file__).with_name('libmd-library-install-plan.py'))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class PicInstallation(unittest.TestCase):
    def setUp(self):
        self.metadata = dict(LIB='sample', _LIBS='libsample.a libsample_pic.a',
                             INSTALL_PIC_ARCHIVE='', MK_INSTALLLIB='yes')

    def test_empty_definition_installs(self):
        self.assertEqual(policy.installed_pic_archive(self.metadata, 'yes'), 'libsample_pic.a')

    def test_undefined_does_not_install(self):
        self.assertIsNone(policy.installed_pic_archive(self.metadata, 'no'))

    def test_value_no_still_defined(self):
        self.metadata['INSTALL_PIC_ARCHIVE'] = 'no'
        self.assertEqual(policy.installed_pic_archive(self.metadata, 'yes'), 'libsample_pic.a')

    def test_independent_of_regular_archive_install_switch(self):
        self.metadata['MK_INSTALLLIB'] = 'no'
        self.assertEqual(policy.installed_pic_archive(self.metadata, 'yes'), 'libsample_pic.a')

    def test_missing_or_mismatched_output_rejected(self):
        for outputs in ('libsample.a', 'libprivatesample_pic.a'):
            with self.subTest(outputs=outputs), self.assertRaises(ValueError):
                policy.installed_pic_archive(dict(self.metadata, _LIBS=outputs), 'yes')

    def test_shared_file_flags_preserved(self):
        self.assertEqual(policy.shared_file_flags('-fschg -S'), 'schg')
        self.assertEqual(policy.shared_file_flags('-S -fschg'), 'schg')
        self.assertIsNone(policy.shared_file_flags('-S'))

    def test_unknown_shared_flags_rejected(self):
        for flags in ('-S -fuchg', '-S -S', '-S -C'):
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                policy.shared_file_flags(flags)

    def test_unknown_definition_state_rejected(self):
        with self.assertRaises(ValueError):
            policy.installed_pic_archive(self.metadata, '')


if __name__ == '__main__':
    unittest.main()
