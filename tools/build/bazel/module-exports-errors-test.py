#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Export application must reject unexpected options and failed objcopy."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('module_exports.py')

class ExportErrors(unittest.TestCase):
    def test_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'module'
            source.write_bytes(b'unchanged input')
            flags = root / 'options'
            output = root / 'output'
            tool = root / 'objcopy'
            tool.write_text('#!/bin/sh\nexit 42\n')
            tool.chmod(0o755)
            for content in ('--remove-section=.text\n', '-Ltwo words\n', '-Lsymbol\n'):
                with self.subTest(content=content):
                    flags.write_text(content)
                    p = subprocess.run([sys.executable, str(SCRIPT), str(tool), str(flags), str(source), str(output)],
                                       capture_output=True, timeout=10)
                    self.assertNotEqual(p.returncode, 0)
                    self.assertFalse(output.exists())
                    self.assertFalse(Path(str(output) + '.rsp').exists())
                    self.assertEqual(source.read_bytes(), b'unchanged input')

if __name__ == '__main__':
    unittest.main()
