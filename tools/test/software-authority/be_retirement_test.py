# SPDX-License-Identifier: BSD-2-Clause
"""Fixture retirement admission only: no ZFS commands, pools, or VMs are run."""
from pathlib import Path
import os
import subprocess
import unittest

class RetirementAdmission(unittest.TestCase):
    def check(self, allowed, **overrides):
        source = Path(__file__).with_name('software-be-guest.sh').read_text()
        start = source.index('retirement_check()\n')
        end = source.index('# End retirement admission helper.', start)
        helper = source[start:end]
        shim = r'''
zfs() {
 case "$5:$6" in
  guid:pool/ROOT/candidate) printf '%s\n' "$actual_candidate" ;;
  guid:pool/ROOT/default) printf '%s\n' "$actual_survivor" ;;
  mounted:pool/ROOT/candidate) printf '%s\n' "$mounted" ;;
  *) return 99 ;;
 esac
 [ "$fail_query" != "$5:$6" ]
}
zpool() {
 [ "$5:$6" = bootfs:pool ] || return 99
 printf '%s\n' "$bootfs"
 [ "$fail_query" != bootfs ]
}
bectl() {
 [ "$*" = '-r pool/ROOT list -H' ] || return 99
 printf '%s\n' "$be_listing"
 [ "$fail_query" != bectl ]
}
retirement_check pool/ROOT/candidate "$expected_candidate" pool/ROOT/default "$expected_survivor"
'''
        environment = dict(os.environ, actual_candidate='11', actual_survivor='12',
            expected_candidate='11', expected_survivor='12', mounted='no',
            root_dataset='pool/ROOT/default', bootfs='pool/ROOT/default', fail_query='',
            be_listing='candidate\t-\t-\t1M\t2026-10-22 00:00')
        environment.update(overrides)
        result = subprocess.run(['sh', '-c', helper + shim], env=environment,
            capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_unchanged_inactive_candidate(self):
        self.check(True)

    def test_replacement_and_live_selection(self):
        for changed in (dict(actual_candidate='99'), dict(actual_survivor='99'),
                        dict(mounted='yes'), dict(root_dataset='pool/ROOT/candidate'),
                        dict(bootfs='pool/ROOT/candidate'), dict(bootfs='-')):
            with self.subTest(changed=changed):
                self.check(False, **changed)

    def test_boot_selection_and_listing(self):
        for status in ('N', 'R', 'T', 'NR', 'NR T', '', 'unknown'):
            with self.subTest(status=status):
                self.check(False, be_listing=f'candidate\t{status}\t-\t1M\tdate')
        for listing in ('', 'other\t-\t-\t1M\tdate',
                        'candidate\t-\t/mounted\t1M\tdate',
                        'candidate\t-\t-',
                        'candidate\t-\t-\t1M\tdate\n' * 2):
            with self.subTest(listing=listing):
                self.check(False, be_listing=listing)

    def test_invalid_recorded_identity(self):
        for name in ('expected_candidate', 'expected_survivor'):
            for value in ('', '0', '1:2', 'word', '12\n12'):
                with self.subTest(name=name, value=value):
                    self.check(False, **{name: value})

    def test_failed_query_even_with_plausible_output(self):
        for query in ('guid:pool/ROOT/candidate', 'guid:pool/ROOT/default',
                      'mounted:pool/ROOT/candidate', 'bootfs', 'bectl'):
            with self.subTest(query=query):
                self.check(False, fail_query=query)

if __name__ == '__main__':
    unittest.main()
