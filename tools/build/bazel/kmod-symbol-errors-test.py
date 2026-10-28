#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Module symbol transforms consume checked listings, without hidden subprocesses."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[3]

class SymbolErrors(unittest.TestCase):
    def test_listing_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exports = root / 'exports'
            exports.write_text('exported\n')
            listing = root / 'symbols'
            listing.write_text('00000000 T exported\n00000010 T hidden\n00000008 C common\n         U external\n')
            for script in ('kmod_syms.awk', 'kmod_syms_prefix.awk'):
                for source in (listing, root / 'missing'):
                    with self.subTest(script=script, source=source.name):
                        result = subprocess.run([shutil.which('awk'), '-v', 'prefix=test_', '-f',
                            str(SOURCE / 'sys/conf' / script), str(source),
                            str(exports) if script=='kmod_syms.awk' else '/dev/null'],
                            env={'PATH': '/nonexistent', 'NM': '/nonexistent/nm'},
                            capture_output=True, timeout=10)
                        if source != listing:
                            self.assertNotEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(result.stdout, b'')
                        else:
                            self.assertEqual(result.returncode, 0, result.stderr)
                            expected = {b'-Lhidden', b'-Ncommon'} if script=='kmod_syms.awk' else {
                                b'--redefine-sym=exported=test_exported',
                                b'--redefine-sym=hidden=test_hidden',
                                b'--redefine-sym=common=test_common'}
                            self.assertEqual(set(result.stdout.splitlines()), expected)

if __name__ == '__main__':
    unittest.main()
