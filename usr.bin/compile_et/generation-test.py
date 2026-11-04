# SPDX-License-Identifier: BSD-2-Clause
"""Exercise real compile_et generation and error handling in private directories."""
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest

ROOT = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"]
PROGRAM, SAMPLE, *LIBRARIES = [ROOT / value for value in sys.argv[1:]]
sys.argv[1:] = []

class Generation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"])
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        for library in LIBRARIES:
            self.assertTrue(library.is_file(), str(library))
        self.env = dict(os.environ, LC_ALL="C", LD_LIBRARY_PATH=":".join(sorted({str(p.parent) for p in LIBRARIES})))
    def run_tool(self, filename):
        return subprocess.run([str(PROGRAM), filename], cwd=self.work, env=self.env, capture_output=True, timeout=20)
    def test_sparse_indices_prefix_reset_and_repeated_generation(self):
        source = SAMPLE
        (self.work / "sample.et").write_bytes(source.read_bytes())
        result = self.run_tool("sample.et")
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))
        header = (self.work / "sample.h").read_text()
        c = (self.work / "sample.c").read_text()
        # The independent numeric example uses A=1 and B=2, six bits per
        # character and eight bits reserved for the error index: base 16896.
        for text in ["TEST_FIRST = 16896", "TEST_FOURTH = 16899", "BARE = 16900", "#define ERROR_TABLE_BASE_AB 16896"]:
            self.assertIn(text, header)
        for text in ['/* 000 */ N_("first error")', '/* 001 */ "Reserved AB error (1)"', '/* 002 */ "Reserved AB error (2)"', '/* 003 */ N_("fourth error")', '/* 004 */ N_("bare error")', '#define num_errors 5', 'initialize_error_table_r(list, AB_error_strings, num_errors, ERROR_TABLE_BASE_AB)']:
            self.assertIn(text, c)
        self.assertEqual({p.name for p in self.work.iterdir()}, {"sample.et", "sample.h", "sample.c"})
        self.assertEqual(self.run_tool("sample.et").returncode, 0)
        self.assertEqual((self.work / "sample.h").read_text(), header)
        self.assertEqual((self.work / "sample.c").read_text(), c)
    def test_invalid_table_does_not_emit_outputs(self):
        (self.work / "invalid.et").write_text('error_table TOOLONG\nerror_code BAD, "bad"\nend\n')
        result = self.run_tool("invalid.et")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"table name too long", result.stderr)
        self.assertEqual({p.name for p in self.work.iterdir()}, {"invalid.et"})
    def test_missing_input_does_not_emit_outputs(self):
        result = self.run_tool("missing.et")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"missing.et", result.stderr)
        self.assertEqual(list(self.work.iterdir()), [])

if __name__ == "__main__": unittest.main()
