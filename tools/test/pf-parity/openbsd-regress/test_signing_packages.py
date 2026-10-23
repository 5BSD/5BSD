#!/usr/bin/env python3
"""Installed signing package tags must have maintained package targets."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[4]
PACKAGES = {'libcapimage': ('dbg', 'dev', 'man'), 'capsign': ('dbg', 'man'), 'bsd-build': ('dbg', 'man'), 'libcapimage-tests': ('dbg',), 'capsign-tests': ('dbg',), 'bsd-build-tests': ()}
class SigningPackages(unittest.TestCase):
    def test_variants(self):
        with tempfile.TemporaryDirectory() as temp:
            for name, variants in PACKAGES.items():
                for debug in (False, True):
                    for man in (False, True):
                        actual = subprocess.check_output(['make', '-C', str(ROOT/'packages'/name), '-V', '_ALLPACKAGES', 'REPODIR='+temp, 'PKG_VERSION=1', 'PKG_ABI=FreeBSD:16:amd64', ('WITH_' if debug else 'WITHOUT_')+'DEBUG_FILES=yes', ('WITH_' if man else 'WITHOUT_')+'MANSPLITPKG=yes'], text=True).split()
                        expected = [name]+[name+'-'+v for v in variants if (v!='dbg' or debug) and (v!='man' or man)]
                        self.assertEqual(sorted(actual), sorted(expected), name)
    def test_parent_inventory_and_link_dependency(self):
        s=(ROOT/'packages/Makefile').read_text()
        for name in PACKAGES:
            self.assertIn(name, s)
        self.assertIn('PKG_DEPS.libcapbundle+=\tlibcapimage', (ROOT/'packages/libcapbundle/Makefile').read_text())
if __name__=='__main__': unittest.main()
