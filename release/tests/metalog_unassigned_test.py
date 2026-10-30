# SPDX-License-Identifier: BSD-2-Clause
"""Test unassigned-file discovery through the maintained METALOG parser."""
from pathlib import Path
import subprocess
import tempfile
import unittest

READER = Path(__file__).resolve().parents[2] / 'tools/pkgbase/metalog_reader.lua'


class Unassigned(unittest.TestCase):
    def run_report(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'METALOG'
            path.write_text(text)
            p = subprocess.run(['/usr/libexec/flua', str(READER), '-u', str(path)],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            return p.stdout.splitlines()

    def test_files_links_and_scaffolding(self):
        self.assertEqual(self.run_report(
            './etc type=dir mode=0755\n'
            './etc/generated type=file mode=0644\n'
            './etc/link type=link link=generated mode=0777\n'
            './etc/config type=file mode=0644 tags=package=runtime,config\n'),
            ['./etc/generated', './etc/link'])

    def test_other_tags_are_not_package_assignment(self):
        self.assertEqual(self.run_report(
            './a type=file mode=0644 tags=config\n'
            './b type=file mode=0644 tags=package=\n'), ['./a','./b'])

    def test_any_record_can_supply_ownership(self):
        self.assertEqual(self.run_report(
            './a type=file mode=0644\n'
            './a type=file mode=0644 tags=package=runtime\n'), [])

    def test_sorted_unique_escaped_names(self):
        self.assertEqual(self.run_report(
            './z type=file mode=0644\n'
            './a\\040b type=file mode=0644\n'
            './z type=file mode=0644\n'), ['./a\\040b', './z'])

    def test_empty_assignment_report_is_not_runtime_coverage(self):
        self.assertEqual(self.run_report('./dir type=dir mode=0755\n'), [])


if __name__ == '__main__': unittest.main()
