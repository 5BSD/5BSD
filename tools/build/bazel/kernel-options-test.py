# SPDX-License-Identifier: BSD-2-Clause
"""Keep changed GENERIC defaults and malformed option expectations fail-closed."""
from pathlib import Path
import tempfile
import unittest
from kernel_options import validate_header, validate_directory


class KernelOptionsTest(unittest.TestCase):
    def test_enabled_disabled_and_unrelated_options(self):
        validate_header('#define FDT 1\n#define OTHER 1\n', {'FDT': True, 'ZSTDIO': False})

    def test_changed_default_is_rejected(self):
        for text, expected in [('#define FDT 1\n', False), ('', True)]:
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, 'kernel option FDT differs'):
                validate_header(text, {'FDT': expected})

    def test_undef_and_comments_do_not_enable_option(self):
        validate_header('#undef FDT\n/* #define FDT 1 */\n', {'FDT': False})

    def test_options_from_distinct_generated_headers(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            with self.assertRaisesRegex(ValueError, 'complete generated'):
                validate_directory(directory, {'FDT': False})
            (directory / 'opt_global.h').write_text('#define TCP_HHOOK 1\n')
            (directory / 'opt_platform.h').write_text('#define FDT 1\n')
            (directory / 'opt_zstdio.h').write_text('#define ZSTDIO 1\n')
            validate_directory(directory, {'FDT': True, 'TCP_HHOOK': True, 'ZSTDIO': True})
            with self.assertRaisesRegex(ValueError, 'kernel option FDT differs'):
                validate_directory(directory, {'FDT': False})

    def test_expectations_are_strict(self):
        for expected in [[], {'FDT': 'yes'}, {'FDT': 1}, {'FDT\noptions EVIL': True}]:
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                validate_header('', expected)


if __name__ == '__main__':
    unittest.main()
