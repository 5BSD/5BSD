#!/usr/bin/env python3
"""Parse the shipped inactive PF template without loading rules or interfaces."""
from pathlib import Path
import os
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[4]


class InstalledExamples(unittest.TestCase):
    def test_current_template_and_retirements(self):
        binary = os.environ.get('PFCTL')
        if not binary:
            self.fail('Set PFCTL to the current source-built pfctl (not the host binary)')
        template = (ROOT / 'share/examples/pf/pf.conf').read_text()
        self.assertTrue(all(not line.strip() or line.startswith('#')
                            for line in template.splitlines()))
        rules = '\n'.join(line[1:] for line in template.splitlines()
                          if line.startswith('#') and not line.startswith('##'))
        result = subprocess.run([binary, '-o', 'none', '-nv', '-D', 'ext_if=lo0',
                                 '-D', 'int_if=lo0', '-f', '-'], input=rules,
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('nat-to (lo0)', result.stdout)
        self.assertIn('block drop all', result.stdout)
        self.assertIn('pass out all', result.stdout)
        files = subprocess.check_output(['make', '-C', str(ROOT / 'share/examples/pf'),
                                         '-V', 'FILES'], text=True).split()
        self.assertEqual(sorted(files), ['README', 'pf.conf'])
        obsolete = (ROOT / 'ObsoleteFiles.inc').read_text()
        for name in ['ackpri', 'faq-example1', 'faq-example2', 'faq-example3',
                     'queue1', 'queue2', 'queue3', 'queue4', 'spamd']:
            self.assertIn('OLD_FILES+= usr/share/examples/pf/' + name + '\n', obsolete)


if __name__ == '__main__':
    unittest.main()
