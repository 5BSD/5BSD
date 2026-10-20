#!/usr/bin/env python3
"""Exercise the configured vendor radix recipe beside native radix.c."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]

class RadixObjectRule(unittest.TestCase):
    def test_distinct_native_and_vendor_outputs(self):
        source = (ROOT / 'sys/conf/files').read_text()
        rule = re.search(r'^\.\./contrib/openbsd-pf/sys/net/radix\.c.*?'
                         r'compile-with "([^"]+)".*?obj-prefix "([^"]+)"',
                         source, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(rule)
        recipe, prefix = rule.groups()
        self.assertEqual(prefix, 'obsd_')
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            (p / 'native').mkdir()
            (p / 'vendor').mkdir()
            (p / 'native/radix.c').write_text('int native_radix(void) {return 17;}\n')
            (p / 'vendor/radix.c').write_text(
                '#ifndef OBSD_RADIX_IMPL\n#error Missing implementation guard\n#endif\n'
                'int vendor_radix(void) {return 23;}\n')
            (p / 'main.c').write_text(
                'int native_radix(void); int vendor_radix(void);\n'
                'int main(void) {return native_radix()!=17 || vendor_radix()!=23;}\n')
            (p / 'Makefile').write_text(
                'CC=' + os.environ.get('CC', 'cc') + '\n'
                'OPENBSD_PF_C=${CC} -c\n'
                'all: check\n'
                'radix.o: native/radix.c\n\t${CC} -c ${.ALLSRC}\n'
                + prefix + 'radix.o: vendor/radix.c\n\t' + recipe + ' ${.ALLSRC}\n'
                'check: radix.o ' + prefix + 'radix.o main.c\n'
                '\t${CC} ${.ALLSRC} -o check\n')
            subprocess.run(['make', '-j2', 'all'], cwd=p, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertTrue((p / 'radix.o').is_file())
            self.assertTrue((p / (prefix + 'radix.o')).is_file())
            subprocess.run([str(p / 'check')], check=True)

if __name__ == '__main__':
    unittest.main()
