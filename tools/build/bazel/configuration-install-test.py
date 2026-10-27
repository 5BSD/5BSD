#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check configuration export against effective maintained Make metadata."""
import subprocess
import tempfile
import unittest
from pathlib import Path

import configuration_install


class ConfigurationMetadata(unittest.TestCase):
    def export(self, declarations):
        with tempfile.TemporaryDirectory(prefix='configuration-metadata-') as directory:
            root = Path(directory)
            (root / 'Makefile').write_text(declarations + '''
.include <bsd.init.mk>
.include <bsd.confs.mk>
''')
            source = Path(__file__).resolve().parents[3]

            def query(keys):
                command = ['/usr/bin/make', '-m', str(source / 'share/mk'),
                           'NO_ROOT=yes', 'DB_FROM_SRC=yes', 'BUILD_PKGS=yes']
                command += [arg for key in keys for arg in ('-V', key)]
                result = subprocess.run(command, cwd=root, check=True, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                rows = result.stdout.splitlines()
                self.assertEqual(len(rows), len(keys))
                return dict(zip(keys, rows))

            records = {}

            def add(path, kind, owner, group, mode, tags, **details):
                self.assertNotIn(path, records)
                records[path] = dict(kind=kind, owner=owner, group=group,
                                     mode=mode, tags=tags, **details)

            configuration_install.export(query(['CONFGROUPS']), query, add,
                                         lambda name: dict(source=name))
            return records

    def test_group_defaults_and_per_file_overrides(self):
        records = self.export('''CONFGROUPS= SETTINGS
SETTINGS= defaults.conf private.conf
SETTINGSOWN= root
SETTINGSGRP= wheel
SETTINGSMODE= 0644
SETTINGSDIR= CONFIG_DEST
CONFIG_DEST= /etc/example
SETTINGSNAME_private.conf= renamed.conf
SETTINGSDIR_private.conf= PRIVATE_DEST
PRIVATE_DEST= /var/db/example
SETTINGSOWN_private.conf= daemon
SETTINGSGRP_private.conf= daemon
SETTINGSMODE_private.conf= 0600
SETTINGSPACKAGE= example
''')
        self.assertEqual(set(records), {'/etc/example/defaults.conf',
                                       '/var/db/example/renamed.conf'})
        standard = records['/etc/example/defaults.conf']
        private = records['/var/db/example/renamed.conf']
        self.assertEqual((standard['owner'], standard['group'], standard['mode']),
                         ('root', 'wheel', '0644'))
        self.assertEqual((private['owner'], private['group'], private['mode']),
                         ('daemon', 'daemon', '0600'))
        self.assertEqual(private['source'], 'private.conf')
        for record in records.values():
            self.assertEqual(record['kind'], 'file')
            self.assertEqual(record['role'], 'configuration')
            self.assertEqual(set(record['tags'].split()[-1].split(',')),
                             {'package=example', 'config'})

    def test_disabled_and_empty_groups(self):
        self.assertEqual(self.export('''CONFGROUPS= EMPTY
CONFGROUPS.no= DISABLED
DISABLED= disabled.conf
EMPTY=
'''), {})


if __name__ == '__main__':
    unittest.main()
