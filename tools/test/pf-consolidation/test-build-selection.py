#!/usr/bin/env python3
"""Check the independent firewall/shaper build contract without building or loading."""
from pathlib import Path
import subprocess
import unittest

SRC = Path(__file__).resolve().parents[3]


def subdirs(directory, *options):
    return set(subprocess.check_output(
        ['make', '-C', str(SRC / directory), '-V', 'SUBDIR', *options],
        text=True, stderr=subprocess.PIPE).split())


class BuildSelection(unittest.TestCase):
    def test_pf_shaping_without_ipfw(self):
        world = subdirs('sbin', 'WITHOUT_IPFW=yes')
        modules = subdirs('sys/modules', 'WITHOUT_IPFW=yes')
        graph = subdirs('sys/modules/netgraph', 'WITHOUT_IPFW=yes')
        self.assertTrue({'dnctl', 'pfctl'} <= world)
        self.assertTrue({'dummynet', 'pf'} <= modules)
        for names in [world, modules, graph]:
            self.assertFalse(any('ipfw' in n for n in names), names)

    def test_shaper_can_be_disabled_independently(self):
        world = subdirs('sbin', 'WITHOUT_DUMMYNET=yes')
        modules = subdirs('sys/modules', 'WITHOUT_DUMMYNET=yes')
        self.assertNotIn('dnctl', world)
        self.assertNotIn('dummynet', modules)
        self.assertIn('pfctl', world)
        self.assertIn('pf', modules)

    def test_retired_engine_is_not_reenableable(self):
        for directory in ['sbin', 'sys/modules', 'sys/modules/netgraph']:
            names = subdirs(directory)
            self.assertFalse(any('ipfw' in n for n in names), names)
            result = subprocess.run(
                ['make', '-C', str(SRC / directory), '-V', 'SUBDIR',
                 'WITH_IPFW=yes'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('IPFW has been removed', result.stderr)
        for directory in ['sys/netpfil/ipfw', 'sbin/ipfw',
                          'usr.sbin/ipfwpcap', 'packages/ipfw']:
            self.assertFalse(any(p.is_file() for p in (SRC / directory).rglob('*')))


if __name__ == '__main__':
    unittest.main()
