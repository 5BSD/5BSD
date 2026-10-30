# SPDX-License-Identifier: BSD-2-Clause
import json
import hashlib
from pathlib import Path
import configuration_compose as composition
import os
import subprocess
import unittest


class Normalizer(unittest.TestCase):
    def test_composition_preserves_policy_and_checks_bindings(self):
        helper = Path(os.environ.get('BSD_BUILD_UCL_JSON', '/usr/libexec/bsd-build/bsd-ucl-json'))
        digest = hashlib.sha256(helper.read_bytes()).hexdigest()
        base = b'crypto_recipient="example.Crypto/service"; storage=[];'
        changes = {'format': 1, 'base_sha256': hashlib.sha256(base).hexdigest(),
            'replace': {'storage': {'expected': [], 'value': [{'pool': 'explicit'}]}},
            'add': {}, 'remove': {}}
        output, receipt = composition.compose_ucl(base, changes, helper, digest)
        self.assertEqual(json.loads(output)['crypto_recipient'], 'example.Crypto/service')
        self.assertEqual(receipt['base_sha256'], hashlib.sha256(base).hexdigest())
        self.assertEqual(receipt['parser_sha256'], digest)
        with self.assertRaisesRegex(ValueError, 'parser differs'):
            composition.compose_ucl(base, changes, helper, '0' * 64)
        with self.assertRaisesRegex(ValueError, 'base differs'):
            composition.compose_ucl(base + b' ', changes, helper, digest)
        changes['replace'] = {}
        changes['remove'] = {'crypto_recipient': 'example.Crypto/service'}
        output, _ = composition.compose_ucl(base, changes, helper, digest)
        self.assertNotIn('crypto_recipient', json.loads(output))

    def test_policy_inputs(self):
        helper = os.environ.get('BSD_BUILD_UCL_JSON', '/usr/libexec/bsd-build/bsd-ucl-json')
        cases = [
            ('valid', b'crypto_recipient="example.Crypto/service"; storage=[];', True),
            ('duplicate', b'a=1;a=2;', False),
            ('nested_duplicate', b'a { b=1;b=2; }', False),
            ('include', b'a=1; .include "/etc/passwd";', False),
            ('try_include', b'a=1; .try_include "missing";', False),
            ('priority', b'a=1; .priority 5;', False),
            ('inherit', b'a=1; .inherit a;', False),
            ('unknown_macro', b'a=1; .unknown x;', False),
            ('nul', b'a=1;\x00', False),
            ('oversize', b' ' * 1048577, False),
            ('array', b'[1,2]', False),
            ('literal', b'a="${COMPOSE_SECRET}";', True),
            ('quoted_macro', b'a=".include";', True)]
        for name, data, success in cases:
            with self.subTest(name=name):
                result = subprocess.run([helper], input=data, capture_output=True,
                    timeout=10, env=dict(os.environ, COMPOSE_SECRET='must-not-expand'))
                self.assertEqual(result.returncode == 0, success, result.stderr)
                if success:
                    value = json.loads(result.stdout)
                    if name == 'literal': self.assertEqual(value['a'], '${COMPOSE_SECRET}')
                    if name == 'valid': self.assertEqual(value['storage'], [])
                else:
                    self.assertEqual(result.stdout, b'')


if __name__ == '__main__': unittest.main()
