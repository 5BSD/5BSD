#!/usr/bin/env python3
"""Exercise native target rejection, compatibility builds and firewall selection."""
from pathlib import Path
import subprocess
import re
import unittest

SRC = Path(__file__).resolve().parents[3]


def make(directory='', *args):
    return subprocess.run(['make', '-C', str(SRC / directory), *args],
                          capture_output=True, text=True)


class Retirement(unittest.TestCase):
    def test_native_targets(self):
        result = make('', 'targets')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[1:], [
            '    amd64/amd64', '    arm64/aarch64', '    riscv/riscv64'])
        for target, arch in [('amd64', 'amd64'), ('arm64', 'aarch64'),
                             ('riscv', 'riscv64')]:
            result = make('', '-f', 'Makefile.inc1', f'TARGET={target}',
                          f'TARGET_ARCH={arch}', '-V', 'KNOWN_ARCHES')
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_retired_native_targets_rejected(self):
        for target, arch in [('arm', 'armv7'), ('arm', 'armv6'),
                             ('i386', 'i386'), ('powerpc', 'powerpc'),
                             ('powerpc', 'powerpc64'),
                             ('powerpc', 'powerpc64le')]:
            with self.subTest(target=target, arch=arch):
                for entry in [[], ['-f', 'Makefile.inc1']]:
                    result = make('', *entry, f'TARGET={target}',
                                  f'TARGET_ARCH={arch}', '-V', 'KNOWN_ARCHES')
                    self.assertNotEqual(result.returncode, 0)
                result = make('sys/modules', f'MACHINE={target}',
                              f'MACHINE_ARCH={arch}', '-V', 'SUBDIR')
                self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(make('', 'targets', 'TARGETS=powerpc').returncode, 0)

    def test_compatibility_libraries_retained(self):
        for target, arch in [('arm', 'armv7'), ('i386', 'i386')]:
            result = make('', '-f', 'Makefile.inc1', f'TARGET={target}',
                          f'TARGET_ARCH={arch}', 'COMPAT_LIBCOMPAT=32',
                          '-V', 'KNOWN_ARCHES')
            self.assertEqual(result.returncode, 0, result.stderr)
        for path in ['sys/arm64/arm64/elf32_machdep.c',
                     'sys/compat/freebsd32/freebsd32_misc.c',
                     'sys/arm/include/elf.h', 'sys/i386/include/elf.h']:
            self.assertTrue((SRC / path).is_file(), path)

    def test_no_retired_firewall_consumers(self):
        # Catch orphaned dependency metadata and dormant rescue/startup paths,
        # which checking the default SUBDIR selection alone does not exercise.
        retired = re.compile(r'sbin/ipf/|tags=package=ipf\b|5BSD-ipf\b|ipf\.conf|(?:/etc/rc.d/|\b)(?:ipfs|ipfstat|ipnat|ippool|ipmon)\b')
        for path in ['targets/pseudo/userland/Makefile.depend',
                     'rescue/rescue/Makefile.depend', 'rescue/rescue/Makefile',
                     'libexec/rc/netstart', 'tests/sys/netinet/fibs_test.sh',
                     'contrib/blocklist/etc/Makefile',
                     'contrib/blocklist/port/Makefile.am',
                     'etc/mtree/BSD.var.dist',
                     'release/tools/oci-image-notoolchain.conf']:
            self.assertNotRegex((SRC / path).read_text(), retired, path)
        result = make('rescue/rescue', '-V', 'CRUNCH_PROGS_sbin')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('ipf', result.stdout.split())
        self.assertIn('pfctl', result.stdout.split())

    def test_firewall_and_crypto_selection(self):
        for directory in ['sbin', 'sys/modules']:
            result = make(directory, '-V', 'SUBDIR')
            self.assertEqual(result.returncode, 0, result.stderr)
            names = result.stdout.split()
            self.assertNotIn('ipf', names)
            self.assertNotIn('ipfilter', names)
            self.assertNotIn('safe', names)
            self.assertIn('pf' if directory == 'sys/modules' else 'pfctl', names)
            self.assertIn('dummynet' if directory == 'sys/modules' else 'dnctl', names)
            for option in ['WITH_IPFILTER=yes', 'WITH_IPFILTER_IPFS=yes']:
                result = make(directory, '-V', 'SUBDIR', option)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('IPFilter has been removed', result.stderr)
        self.assertTrue((SRC / 'sys/dev/safexcel').is_dir())


if __name__ == '__main__':
    unittest.main()
