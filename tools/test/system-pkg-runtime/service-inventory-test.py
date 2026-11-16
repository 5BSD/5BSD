# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Exercise the real native bundle parser; missing tools must fail, never skip."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from service_health import inventory


class InstalledInventory(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        if 'SERVICE_INVENTORY' in os.environ:
            self.binary = Path(os.environ['SERVICE_INVENTORY']).resolve(strict=True)
        else:
            self.binary = (Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE'] /
                           'tools/test/system-pkg-runtime/service_inventory').resolve(strict=True)

    def fixture(self):
        bundle = self.root / 'Test.cap';bundle.mkdir()
        (bundle / 'Bundle.ucl').write_text('schema="org.5bsd.capability-bundle"; '
            'bundle_id="org.test.inventory"; version="1.0.0"; sequence=1; '
            'author="test"; publisher="org.test"; units=["bootd","lazy"];')
        for unit, activation in (('bootd', 'boot=true;'), ('lazy', 'ipc=["test.Lazy"];')):
            directory = bundle / 'Units' / (unit + '.unit');(directory / 'bin').mkdir(parents=True)
            program = directory / 'bin' / unit;program.write_text('#!/bin/sh\nexit 0\n');program.chmod(0o755)
            (directory / 'Unit.ucl').write_text('activation {' + activation + '}')
        return bundle

    def test_real_boot_and_on_demand_policies(self):
        self.fixture()
        result = subprocess.run([str(self.binary), str(self.root)], capture_output=True, check=True)
        services = inventory(result.stdout, [str(self.root)])
        self.assertEqual(len(services), 2)
        self.assertEqual([s['label'] for s in services.values() if s['boot']], ['org.test.inventory/bootd'])
        self.assertEqual(services['org.test.inventory/lazy']['endpoints'], ['test.Lazy'])

    def test_invalid_bundle_must_fail(self):
        bundle = self.fixture();(bundle / 'Bundle.ucl').write_text('invalid = true;')
        result = subprocess.run([str(self.binary), str(self.root)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        with self.assertRaises((ValueError, json.JSONDecodeError)):
            inventory(result.stdout, [str(self.root)])

    def test_missing_root_must_fail(self):
        result = subprocess.run([str(self.binary), str(self.root / 'absent')], capture_output=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':unittest.main()
