# SPDX-License-Identifier: BSD-2-Clause
"""Registry filtering and input validation regressions for the native action."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("test_list.py")

class Registry(unittest.TestCase):
    def generate(self, contents, excludes=(), succeeds=True):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as work:
            root = Path(work)
            sources = []
            for index, data in enumerate(contents):
                path = root / (str(index) + ".c")
                path.write_bytes(data)
                sources.append(str(path))
            target = root / "list.h"
            argv = [sys.executable, "-B", "-S", str(SCRIPT)]
            for name in excludes:
                argv += ["--exclude", name]
            run = subprocess.run(argv + [str(target)] + sources, capture_output=True)
            self.assertEqual(run.returncode == 0, succeeds, run.stderr)
            if succeeds:
                return target.read_bytes()
            self.assertFalse(target.exists())
            return run.stderr

    def test_original_anchor_and_input_order(self):
        self.assertEqual(self.generate([b"/* DEFINE_TEST(comment) */\n DEFINE_TEST(indented)\nDEFINE_TEST(first)\n", b"DEFINE_TEST(second)\n"]), b"DEFINE_TEST(first)\nDEFINE_TEST(second)\n")

    def test_original_literal_fragment_exclusion(self):
        self.assertEqual(self.generate([b"DEFINE_TEST(broken)\nDEFINE_TEST(broken_suffix)\nDEFINE_TEST(retained)\n"], ["broken"]), b"DEFINE_TEST(retained)\n")

    def test_grep_newline_and_crlf_bytes(self):
        self.assertEqual(self.generate([b"DEFINE_TEST(crlf)\r\nDEFINE_TEST(no_final_newline)"]), b"DEFINE_TEST(crlf)\r\nDEFINE_TEST(no_final_newline)\n")

    def test_stale_exclusion_rejected(self):
        self.assertIn(b"does not match", self.generate([b"DEFINE_TEST(kept)\n"], ["absent"], False))

    def test_invalid_exclusion_rejected(self):
        self.assertIn(b"C identifiers", self.generate([b"DEFINE_TEST(kept)\n"], [".*"], False))

    def test_empty_selection_rejected(self):
        self.assertIn(b"empty", self.generate([b"DEFINE_TEST(removed)\n"], ["removed"], False))

    def test_binary_source_rejected(self):
        self.assertIn(b"NUL", self.generate([b"DEFINE_TEST(bad)\0\n"], succeeds=False))

if __name__ == "__main__":
    unittest.main()
