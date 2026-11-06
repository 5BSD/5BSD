# SPDX-License-Identifier: BSD-2-Clause
"""Exercise complete ownership boundaries, not just successful partition output."""
import unittest
from world_package_inventory import inventory


def record(path, package='runtime', kind='file', **values):
    result = dict(destination=path, type=kind, owner='root', group='wheel', mode='0755' if kind=='dir' else '0444',
        tags=[] if package is None else ['package='+package])
    result.update(values)
    return result


class Inventory(unittest.TestCase):
    def test_exact_construction_and_library_suffix(self):
        state = record('/etc/pwd.db', None)
        lib = record('/lib/example.so', tags=['package=runtime', 'lib'])
        got = inventory([state, lib], [state], ['dbg', 'dev', 'lib'])
        self.assertEqual(set(got['construction']), {'/etc/pwd.db'})
        self.assertEqual(set(got['packages']), {'runtime-lib'})

    def test_unexplained_or_changed_construction_fails(self):
        state = record('/etc/pwd.db', None)
        for declarations in [[], [dict(state, mode='0600')]]:
            with self.assertRaisesRegex(ValueError, 'exact construction'):
                inventory([state], declarations, [])

    def test_unused_declaration_fails(self):
        with self.assertRaisesRegex(ValueError, 'do not match'):
            inventory([], [record('/etc/pwd.db', None)], [])

    def test_directories_keep_distinct_packages_and_equivalent_claims(self):
        a = record('/usr/lib', kind='dir')
        b = record('/usr/lib', 'clibs', kind='dir')
        got = inventory([a, dict(a, flags=''), dict(a, flags='none', mode='755'), b], [], [])
        self.assertEqual(set(got['packages']), {'runtime', 'clibs'})
        self.assertEqual(len(got['packages']['runtime']), 1)
        self.assertEqual(got['summary']['directory_record_occurrences'], 4)

    def test_equivalent_directory_package_spellings(self):
        a=record('/usr/include',kind='dir',tags=['package=clibs','dev'])
        b=record('/usr/include','clibs-dev',kind='dir')
        got=inventory([a,b],[],['dev'])
        self.assertEqual(len(got['packages']['clibs-dev']),1)

    def test_conflicting_directory_or_duplicate_file_fails(self):
        directory = record('/usr/lib', kind='dir')
        file = record('/usr/lib/data')
        for records in [[directory, dict(directory, mode='0700')], [file, file], [directory, record('/usr/lib')]]:
            with self.assertRaises(ValueError):
                inventory(records, [], [])

    def test_hardlink_ownership_and_cycles(self):
        file = record('/lib/a')
        link = record('/lib/b', kind='hardlink', link='/lib/a')
        inventory([file, link], [], [])
        cross = inventory([file, dict(link, tags=['package=other'])], [], [])
        self.assertEqual(cross['cross_package_hardlinks']['/lib/b'], dict(package='other', target='/lib/a', target_package='runtime'))
        for records in [[file, dict(link, mode='0600')], [dict(link, link='/lib/b')], [dict(link, link='/missing')]]:
            with self.assertRaises(ValueError):
                inventory(records, [], [])

    def test_invalid_tags_and_config_directory_fail(self):
        for tags in [['package=runtime','package=other'], ['package=runtime','unknown'], ['package=runtime','config']]:
            with self.assertRaises(ValueError):
                inventory([record('/usr/lib', kind='dir', tags=tags)], [], [])


if __name__ == '__main__':
    unittest.main()
