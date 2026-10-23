#!/usr/bin/env python3
"""Check the maintained pfsync rc preflight against integrated PF packaging."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[4]

class RcModules(unittest.TestCase):
    def test_integrated_module_satisfies_rc_preflight(self):
        source = (ROOT / 'libexec/rc/rc.d/pfsync').read_text()
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            (p / 'rc.subr').write_text('''
load_rc_config() { :; }
run_rc_command() {
 for module in $required_modules; do
  case "$module" in pf) :;; *) echo "unshipped module: $module" >&2; return 1;; esac
 done
 [ "$required_modules" = pf ]
}
''')
            (p / 'rc').write_text(source.replace('. /etc/rc.subr', '. "' + str(p / 'rc.subr') + '"'))
            subprocess.run(['/bin/sh', str(p / 'rc'), 'start'], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        modules = subprocess.check_output(['make', '-C', str(ROOT / 'sys/modules'),
                    'SRCTOP=' + str(ROOT), '-V', '${SUBDIR}'], text=True).split()
        self.assertIn('pf', modules)
        self.assertNotIn('pfsync', modules)
        self.assertNotIn('pflog', modules)
        programs = subprocess.check_output(['make', '-C', str(ROOT / 'sbin'),
                    'SRCTOP=' + str(ROOT), '-V', '${SUBDIR}'], text=True).split()
        self.assertIn('pfctl', programs)
        self.assertIn('pflogd', programs)
        self.assertNotIn('pflowctl', programs)
        obsolete = (ROOT / 'ObsoleteFiles.inc').read_text()
        for path in ['boot/kernel/pflog.ko', 'boot/kernel/pflow.ko',
                     'boot/kernel/pfsync.ko', 'sbin/pflowctl',
                     'usr/share/man/man8/pflowctl.8.gz']:
            self.assertIn('OLD_FILES+= ' + path + '\n', obsolete)

if __name__ == '__main__': unittest.main()
