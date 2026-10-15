#!/usr/bin/env python3
"""Exercise real helper scripts with controller/config paths redirected to fixtures.

The fake pfctl answers in OpenBSD pfctl's formats (5BSD's pfctl is OpenBSD's):
"-s Anchors" lists child anchors as "  parent/child".
"""
import pathlib
import subprocess
import tempfile
import unittest

SRC = pathlib.Path(__file__).resolve().parents[3]
HELPERS = ['contrib/blocklist/libexec/blocklistd-helper',
           'libexec/blocklistd-helper/blacklistd-helper']


class BlocklistRetirement(unittest.TestCase):
    def run_fixture(self, helper, action, legacy=None):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / 'etc').mkdir()
            (root / 'sbin').mkdir()
            log = root / 'calls'
            ctl = root / 'sbin/pfctl'
            ctl.write_text('#!/bin/sh\n'
                'echo "$*" >> "' + str(log) + '"\n'
                'case "$*" in\n'
                '  -si) echo "Status: Enabled for 0 days" ;;\n'
                '  *"-f -"*) cat >> "' + str(log) + '" ;;\n'
                '  *"-s Anchors"*) echo "  blocklistd/22" ;;\n'
                'esac\nexit 0\n')
            ctl.chmod(0o755)
            marker = root / 'sourced'
            if legacy:
                (root / 'etc' / legacy).write_text('touch "' + str(marker) + '"\n')
            script = root / 'helper'
            source = (SRC / helper).read_text()
            # Only absolute filesystem locations change; helper control flow is real.
            for prefix in ['/usr/sbin/', '/sbin/', '/etc/']:
                source = source.replace(prefix, str(root) + prefix)
            script.write_text(source)
            result = subprocess.run(['/bin/sh', str(script), action, 'blocklistd',
                'tcp', '192.0.2.99', '32', '22', 'test'], capture_output=True, text=True)
            calls = log.read_text() if log.exists() else ''
            return result, calls, marker.exists()

    def test_pf_add_remove_flush(self):
        for helper in HELPERS:
            for action, expected in [('add', '-T add 192.0.2.99/32'),
                                     ('rem', '-T delete 192.0.2.99/32'),
                                     ('flush', '-s Anchors')]:
                with self.subTest(helper=helper, action=action):
                    result, calls, sourced = self.run_fixture(helper, action)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertIn('OK', result.stdout)
                    self.assertIn(expected, calls)
                    self.assertNotIn('ipfw', calls)
                    self.assertFalse(sourced)

    def test_pf_openbsd_rule_and_anchor_flush(self):
        for helper in HELPERS:
            with self.subTest(helper=helper, action='add'):
                result, calls, _ = self.run_fixture(helper, 'add')
                self.assertEqual(0, result.returncode, result.stderr)
                # The block rule is loaded into the per-port anchor in
                # OpenBSD pf.conf syntax (checked with pfctl -n on 5BSD).
                self.assertIn('-a blocklistd/22 -f -', calls)
                self.assertIn('block in quick proto tcp from <port22> '
                              'to any port 22', calls)
                self.assertIn('-qk 192.0.2.99', calls)
            with self.subTest(helper=helper, action='flush'):
                result, calls, _ = self.run_fixture(helper, 'flush')
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn('-a blocklistd/22 -t port22 -T flush', calls)
                self.assertIn('-a blocklistd/22 -F rules', calls)

    def test_legacy_policy_fails_without_execution(self):
        for helper in HELPERS:
            for legacy in ['ipfw-blocklist.rc', 'ipfw-blacklist.rc']:
                with self.subTest(helper=helper, legacy=legacy):
                    result, calls, sourced = self.run_fixture(helper, 'add', legacy)
                    self.assertEqual(1, result.returncode)
                    self.assertIn('migrate blocklist policy to PF', result.stderr)
                    self.assertEqual('', calls)
                    self.assertFalse(sourced)


if __name__ == '__main__':
    unittest.main()
