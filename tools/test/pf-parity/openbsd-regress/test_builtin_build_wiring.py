#!/usr/bin/env python3
"""Check generated built-in PF rules against the maintained module inventory."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]

class BuiltinWiring(unittest.TestCase):
    def test_generated_pf_and_lint_rules(self):
        sources = subprocess.check_output(
            ['make', '-C', str(ROOT / 'sys/modules/pf'), 'SRCTOP=' + str(ROOT),
             '-V', '${SRCS:M*.c}'], text=True).split()
        self.assertTrue(sources)
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            for name, config in [
                ('PF', 'include GENERIC\nident PF_WIRING_TEST\ndevice pf\n'),
                ('LINT', '\n'.join('include "' + str(ROOT / f) + '"' for f in
                 ['sys/conf/NOTES', 'sys/x86/conf/NOTES', 'sys/amd64/conf/NOTES']) + '\n')]:
                cf = p / name
                cf.write_text(config)
                out = p / (name + '-obj')
                subprocess.run([os.environ.get('CONFIG', '/usr/sbin/config'),
                                '-s', str(ROOT / 'sys'), '-d', str(out), str(cf)],
                               cwd=ROOT / 'sys/amd64/conf', check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                generated = (out / 'Makefile').read_text()
                self.assertNotIn('$S/netpfil/pf/', generated)
                for src in sources:
                    obj = ('obsd_' if src == 'radix.c' else '') + src[:-2] + '.o'
                    rule = re.search('^' + re.escape(obj) + r': ([^\n]+)\n\t([^\n]+)',
                                     generated, re.MULTILINE)
                    self.assertIsNotNone(rule, src)
                    self.assertIn('${OPENBSD_PF_C}', rule.group(2))
                    if src == 'radix.c':
                        self.assertIn('-o ${.TARGET}', rule.group(2))
                    if 'netpfil/openbsd-pf/' in rule.group(1):
                        self.assertIn('-DOPENBSD_PF_GLUE', rule.group(2))
                self.assertIn('radix.o: $S/net/radix.c', generated)

if __name__ == '__main__':
    unittest.main()
