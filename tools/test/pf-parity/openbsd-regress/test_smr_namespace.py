#!/usr/bin/env python3
"""Keep the PF entry initializer distinct from native SMR startup."""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]

class SmrNamespace(unittest.TestCase):
    def test_native_and_vendor_initializer_coexist(self):
        header = (ROOT / 'sys/netpfil/openbsd-pf/openbsd_compat.h').read_text()
        source = (ROOT / 'sys/netpfil/openbsd-pf/openbsd_compat.c').read_text()
        aliases = '\n'.join(re.findall(r'^#define\s+smr_init\s+\w+\s*$',
                                        header, re.MULTILINE)) + '\n'
        body = re.search(r'void\nsmr_init\(struct smr_entry \*e\)\n\{.*?\n\}',
                         source, re.DOTALL).group(0)
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            (p / 'native.c').write_text(
                'int smr_init(void) {return 19;}\n'
                'int native_start(void) {return smr_init();}\n')
            (p / 'vendor.c').write_text(
                '#include <string.h>\nstruct smr_entry { unsigned char bytes[64]; };\n'
                + aliases + body + '\n'
                'int native_start(void);\n'
                'int main(void) { struct smr_entry e; unsigned i;\n'
                'memset(&e, 255, sizeof(e)); smr_init(&e);\n'
                'for (i=0; i<sizeof(e.bytes); i++) if(e.bytes[i]) return 1;\n'
                'return native_start()!=19; }\n')
            subprocess.run(shlex.split(os.environ.get('CC', 'cc')) +
                           ['-Wall', '-Wextra', '-Werror', str(p / 'native.c'),
                            str(p / 'vendor.c'), '-o', str(p / 'test')],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run([str(p / 'test')], check=True)

if __name__ == '__main__':
    unittest.main()
