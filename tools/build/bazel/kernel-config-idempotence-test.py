# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Check declarative config against the original native parser on real sources."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import kernel_config
from kernel_options import defined_options, validate_directory

parser = argparse.ArgumentParser()
parser.add_argument('--tool', type=Path, required=True)
parser.add_argument('--anchor', type=Path, required=True)
parser.add_argument('--architecture', choices=['amd64', 'arm64', 'riscv'], required=True)
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining
runfiles = Path(os.environ.get('TEST_SRCDIR', '/'))
# Preserve the declared runfiles namespace rather than resolving a source
# symlink and accidentally reading undeclared siblings from the host checkout.
args.tool = (runfiles / args.tool).absolute()
args.anchor = (runfiles / args.anchor).absolute()
source = args.anchor.parent.parent
config = source / args.architecture / 'conf/GENERIC'


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.control = self.root / 'control'
        self.original(config, self.control)
        self.defined = defined_options(self.control)

    def original(self, selected, output):
        result = subprocess.run([str(args.tool), '-J', '-g', '-d', str(output), '-s',
                        os.path.relpath(source, output), str(selected)],
                       cwd=config.parent, env=os.environ, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def generate(self, settings, expected):
        output = self.root / 'actual'
        active = self.root / 'active-options'
        selected = kernel_config.generate(args.tool, config, source, output, True,
                    {'format': 1, 'settings': settings}, expected, active, os.environ)
        return output, active, selected

    def test_noop_preserves_original_embedded_configuration(self):
        names = ['TCP_HHOOK', 'NFS_ROOT', 'ZSTDIO']
        expected = {name: name in self.defined for name in names}
        settings = [{'option': name, 'enabled': value, 'device': None}
                    for name, value in expected.items()]
        output, active, selected = self.generate(settings, expected)
        self.assertEqual(selected, config)
        self.assertEqual(active.read_bytes(), b'')
        self.assertEqual((output / 'config.c').read_bytes(), (self.control / 'config.c').read_bytes())
        validate_directory(output, expected)

    def test_real_change_matches_independent_parser(self):
        enabled = 'ZSTDIO' not in self.defined
        expected = {'ZSTDIO': enabled}
        output, active, selected = self.generate([{'option': 'ZSTDIO', 'enabled': enabled, 'device': None}], expected)
        self.assertEqual(selected, active)
        reference = self.root / 'changed-reference.conf'
        reference.write_text('include "GENERIC"\n' + ('options' if enabled else 'nooptions') + ' ZSTDIO\n')
        control = self.root / 'changed-control'
        self.original(reference, control)
        self.assertEqual((output / 'config.c').read_bytes(), (control / 'config.c').read_bytes())
        validate_directory(output, expected)

    def test_enable_absent_option_matches_independent_parser(self):
        self.assertNotIn('TCP_SIGNATURE', self.defined)
        expected = {'TCP_SIGNATURE': True}
        output, _, _ = self.generate([{'option': 'TCP_SIGNATURE', 'enabled': True, 'device': None}], expected)
        reference = self.root / 'enabled-reference.conf'
        reference.write_text('include "GENERIC"\noptions TCP_SIGNATURE\n')
        control = self.root / 'enabled-control'
        self.original(reference, control)
        self.assertEqual((output / 'config.c').read_bytes(), (control / 'config.c').read_bytes())
        validate_directory(output, expected)

    def test_declared_default_drift_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'differs from its declared setting/default'):
            self.generate([], {'ZSTDIO': 'ZSTDIO' not in self.defined})

    def test_empty_declared_tree_output_is_supported(self):
        (self.root / 'actual').mkdir()
        output, active, selected = self.generate([], {})
        self.assertEqual(selected, config)
        self.assertEqual(active.read_bytes(), b'')
        self.assertEqual((output / 'config.c').read_bytes(), (self.control / 'config.c').read_bytes())

    def test_stale_output_is_not_adopted(self):
        output = self.root / 'actual'
        output.mkdir()
        (output / 'stale').write_text('old input')
        with self.assertRaisesRegex(ValueError, 'fresh kernel configuration outputs required'):
            self.generate([], {})


if __name__ == '__main__':
    unittest.main()
