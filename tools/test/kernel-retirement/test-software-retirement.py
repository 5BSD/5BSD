#!/usr/bin/env python3
"""Check removal boundaries through kernel configuration and build selection."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SRC = Path(__file__).resolve().parents[3]
POLICIES = ['mac_' + x for x in 'biba mls lomac bsdextended partition seeotheruids ifoff ipacl'.split()]


def make(directory, *args):
    return subprocess.run(['make', '-C', str(SRC / directory), *args],
                          text=True, capture_output=True)


class SoftwareRetirement(unittest.TestCase):
    def test_module_selection_retains_linux_security_and_storage(self):
        for extra in ([], ['ALL_MODULES=yes', 'WITH_TESTS=yes']):
            r = make('sys/modules', *extra, '-V', 'SUBDIR')
            self.assertEqual(r.returncode, 0, r.stderr)
            modules = r.stdout.split()
            for n in ['procfs', 'aout'] + POLICIES:
                self.assertNotIn(n, modules)
            for n in ['linprocfs', 'linsysfs', 'linux64', 'linux_common',
                      'pseudofs', 'fdescfs', 'zfs', 'ufs', 'pf']:
                self.assertIn(n, modules)
        r = make('sys/modules/geom', 'ALL_MODULES=yes', '-V', 'SUBDIR')
        self.assertEqual(r.returncode, 0, r.stderr)
        modules = r.stdout.split()
        for n in ['ccd', 'journal', 'raid3', 'shsec', 'virstor', 'cache',
                  'concat', 'mountver', 'stripe', 'union', 'zero']:
            self.assertNotIn('geom_' + n, modules)
        for n in ['eli', 'part', 'label', 'linux_lvm', 'mirror', 'multipath',
                  'nop', 'raid', 'uzip', 'zoned']:
            self.assertIn('geom_' + n, modules)
        r = make('sys/modules/netgraph', 'ALL_MODULES=yes', '-V', 'SUBDIR')
        self.assertEqual(r.returncode, 0, r.stderr)
        modules = r.stdout.split()
        for n in ['cisco', 'frame_relay', 'lmi', 'rfc1490', 'pred1']:
            self.assertNotIn(n, modules)
        for n in ['bluetooth', 'netgraph', 'socket', 'ppp', 'pppoe', 'vjc']:
            self.assertIn(n, modules)
        r = make('sys/modules', 'ALL_MODULES=yes', '-V', 'SUBDIR')
        self.assertEqual(r.returncode, 0, r.stderr)
        for n in ['udf', 'udf_iconv', 'fdc', 'agp', 'cardbus', 'cbb', 'exca',
                  'ppbus', 'ppc', 'linux', '3dfx', '3dfx_linux',
                  'glxiic', 'glxsb', 'pst', 'sbni']:
            self.assertNotIn(n, r.stdout.split())
        for n in ['aac', 'aacraid', 'ipmi', 'mfi', 'mrsas', 'linux_ntsync']:
            self.assertIn(n, r.stdout.split())
        for n in ['aac', 'aacraid', 'ipmi', 'mfi', 'mrsas']:
            r = make('sys/modules/' + n, '-V', 'SUBDIR')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(n + '_linux', r.stdout.split())
            adapter = (SRC / 'sys/dev' / n / (n + '_linux.c')).read_text()
            self.assertIn('machine/../linux/linux_proto.h', adapter)
            self.assertNotIn('linux32', adapter)
            self.assertIn('MODULE_DEPEND(' + n + '_linux, linux64,', adapter)

    def test_world_and_rescue_selection(self):
        for directory, retired in [('lib', 'libugidfw'), ('usr.sbin', 'ugidfw'),
                                   ('sbin', 'ccdconfig'), ('share', 'security')]:
            r = make(directory, '-V', 'SUBDIR')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn(retired, r.stdout.split())
        r = make('rescue/rescue', '-V', 'CRUNCH_PROGS_sbin')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn('ccdconfig', r.stdout.split())
        self.assertIn('pfctl', r.stdout.split())
        r = make('lib/geom', '-V', 'GEOM_CLASSES')
        self.assertEqual(r.returncode, 0, r.stderr)
        for n in ['journal', 'raid3', 'shsec', 'virstor', 'cache', 'concat',
                  'mountver', 'stripe', 'union']:
            self.assertNotIn(n, r.stdout.split())
        for n in ['eli', 'label', 'part', 'mirror', 'multipath', 'nop', 'raid']:
            self.assertIn(n, r.stdout.split())
        for directory, retired in [('usr.bin', 'ldd32'),
                                   ('libexec', 'rtld-elf32')]:
            r = make(directory, '-V', 'SUBDIR')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn(retired, r.stdout.split())
        self.assertNotIn('ld-elf32.so.1',
                         (SRC / 'libexec/rc/rc.d/ldconfig').read_text())
        self.assertNotIn('LD_32_PRELOAD',
                         (SRC / 'usr.bin/stdbuf/stdbuf.c').read_text())
        r = make('share/man/man4', '-V', 'MAN')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn('aout.4', r.stdout.split())

    def test_installer_does_not_offer_retired_policies(self):
        # Check the shipped installer sources, not an assumed dialog name.
        for path in (SRC / 'usr.sbin/bsdinstall').rglob('*'):
            if path.is_file():
                text = path.read_text(errors='replace')
                for policy in POLICIES:
                    self.assertNotIn(policy, text, str(path))

    def test_retired_kernel_options_are_rejected(self):
        confdir = SRC / 'sys/amd64/conf'
        for option in ['PROCFS', 'COMPAT_AOUT', 'COMPAT_43TTY',
                       'COMPAT_FREEBSD4', 'COMPAT_FREEBSD5', 'COMPAT_FREEBSD6',
                       'COMPAT_FREEBSD7', 'GEOM_JOURNAL', 'UFS_GJOURNAL',
                       'GEOM_RAID3', 'GEOM_SHSEC', 'GEOM_VIRSTOR',
                       'COMPAT_FREEBSD32', 'UDF', 'UDF_ICONV',
                       'GEOM_CACHE', 'GEOM_CONCAT', 'GEOM_STRIPE',
                       'GEOM_ZERO', 'GEOM_VINUM', 'NETGRAPH_CISCO',
                       'NETGRAPH_PRED1'] + [x.upper() for x in POLICIES]:
            with self.subTest(option=option), tempfile.TemporaryDirectory() as tmp:
                p = Path(tmp)
                (p/'TEST').write_text('include GENERIC-NODEBUG\noptions '+option+'\n')
                r = subprocess.run(['config', '-d', str(p/'obj'), str(p/'TEST')],
                                   cwd=confdir, text=True, capture_output=True)
                self.assertNotEqual(r.returncode, 0, option)
                self.assertIn(option, r.stderr + r.stdout)


if __name__ == '__main__':
    unittest.main()
