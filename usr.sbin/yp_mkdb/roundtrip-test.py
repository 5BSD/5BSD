# SPDX-License-Identifier: BSD-2-Clause
"""Local NIS map contracts; no domain mutation, RPC clear or service access."""
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest


class MapRoundTrip(unittest.TestCase):
    def setUp(self):
        root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
        self.program = root / 'usr.sbin/yp_mkdb/yp_mkdb'
        libraries = [root / 'lib/libc/libc.so.7', root / 'lib/libsys/libsys.so.7']
        self.assertTrue(self.program.is_file())
        self.assertTrue(all(path.is_file() for path in libraries))
        self.env = dict(os.environ, LC_ALL='C', LD_LIBRARY_PATH=':'.join(str(path.parent) for path in libraries))
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR'])
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def run_map(self, *args):
        return subprocess.run([str(self.program), *map(str, args)], env=self.env,
                              capture_output=True, text=True, timeout=10)

    def create(self, text, flags=()):
        source = self.directory / 'source'
        source.write_text(text)
        database = self.directory / 'map.db'
        before = int(time.time())
        result = self.run_map(*flags, '-d', 'qualification.invalid', '-m', 'master.invalid',
                              '-i', 'source-label', '-o', 'output-label', source, database)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(database.stat().st_mode), 0o600)
        dumped = self.run_map('-u', database)
        self.assertEqual(dumped.returncode, 0, dumped.stderr)
        self.assertEqual(dumped.stderr, '')
        rows = [line.split(' ', 1) for line in dumped.stdout.splitlines()]
        self.assertTrue(all(len(row) == 2 for row in rows))
        entries = dict(rows)
        self.assertEqual(len(entries), len(rows))
        timestamp = entries.pop('YP_LAST_MODIFIED')
        self.assertTrue(timestamp.isdecimal())
        self.assertLessEqual(before, int(timestamp))
        self.assertLessEqual(int(timestamp), int(time.time()))
        self.assertEqual(entries.pop('YP_MASTER_NAME'), 'master.invalid')
        self.assertEqual(entries.pop('YP_DOMAIN_NAME'), 'qualification.invalid')
        self.assertEqual(entries.pop('YP_INPUT_FILE'), 'source-label')
        self.assertEqual(entries.pop('YP_OUTPUT_FILE'), 'output-label')
        return source, database, entries, result

    def test_round_trip_and_exclusive_creation(self):
        source, database, entries, result = self.create('alpha first\nbeta second value\n')
        self.assertEqual(result.stderr, '')
        self.assertEqual(entries, {'alpha': 'first', 'beta': 'second value'})
        payload = database.read_bytes()
        duplicate = self.run_map('-m', 'master.invalid', source, database)
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertEqual(database.read_bytes(), payload)

    def test_secure_interdomain_and_duplicate_keys(self):
        _, _, entries, result = self.create('alpha first\nalpha ignored\nbeta continued\\\nvalue\n', ('-b', '-s'))
        self.assertIn('duplicate key', result.stderr)
        self.assertEqual(entries, {'alpha': 'first', 'beta': 'continuedvalue', 'YP_SECURE': '', 'YP_INTERDOMAIN': ''})

    def test_filter_plusminus(self):
        _, _, entries, result = self.create('alpha first\n+skip bad\n-skip bad\nbeta +bad\ngamma accepted\n', ('-f',))
        self.assertIn('bad character at start of line', result.stderr)
        self.assertEqual(entries, {'alpha': 'first', 'gamma': 'accepted'})


if __name__ == '__main__':
    unittest.main()
