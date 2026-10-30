#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check generator failure propagation and declared input/output directories."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

class GeneratorTests(unittest.TestCase):
    def run_generator(self, body):
        temporary = tempfile.TemporaryDirectory(prefix='shell generator ')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        script = root / 'generator.py'
        script.write_text(body)
        command = [sys.executable, str(Path(__file__).with_name('generator.py')),
                   '--tool', sys.executable, '--argument', str(script),
                   '--output-dir', str(root / 'outputs')]
        return root, subprocess.run(command, capture_output=True, text=True)

    def test_output_directory(self):
        root, result = self.run_generator(
            "from pathlib import Path\nPath('result').write_text('generated')\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((root / 'outputs/result').read_text(), 'generated')

    def test_nonzero_status(self):
        _, result = self.run_generator('raise SystemExit(7)\n')
        self.assertEqual(result.returncode, 7)

    def test_hidden_diagnostic(self):
        _, result = self.run_generator(
            "import sys\nprint('missing generator tool', file=sys.stderr)\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('missing generator tool', result.stderr)

if __name__ == '__main__':
    unittest.main()
