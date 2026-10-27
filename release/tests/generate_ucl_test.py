# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the real package UCL generator; no package installation is performed."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

GENERATOR = Path(os.environ.get('GENERATE_UCL',
    str(Path(__file__).resolve().parents[1] / 'packages/generate-ucl.lua')))
FLUA = os.environ.get('FLUA', '/usr/libexec/flua')


class Annotations(unittest.TestCase):
    def generate(self, annotations, package='example', variables=(), raw_source=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / 'input.ucl', root / 'output.ucl'
            source.write_text(annotations if raw_source else 'name="5BSD-' + package + '"; comment="example"; desc="fixture";\n' + annotations)
            result = subprocess.run([FLUA, str(GENERATOR), 'PKGNAME', package,
                'PKGGENNAME', 'example', 'PKG_NAME_PREFIX', '5BSD', 'VERSION', '1',
                *variables, str(source), str(output)], capture_output=True, text=True)
            if result.returncode:
                self.assertFalse(output.exists())
                return result, None
            # Reparse emitted UCL, matching the downstream package reader's input.
            reader = root / 'read.lua'
            reader.write_text('local ucl=require("ucl"); local p=ucl.parser(0); '
                'assert(p:parse_file(arg[1])); print(ucl.to_format(p:get_object(), "json"))')
            parsed = subprocess.run([FLUA, str(reader), str(output)], check=True,
                                    capture_output=True, text=True)
            return result, json.loads(parsed.stdout)

    def test_package_and_build_annotations_survive(self):
        declaration = '{"format":1,"actions":[{"name":"site-selected-input"}]}'
        source = 'annotations {"5bsd.construction" = ' + json.dumps(declaration) + ';}\n'
        source += 'annotations {set="minimal,minimal-jail";}'
        result, obj = self.generate(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(obj['annotations'], {'5bsd.construction': declaration, 'set': 'minimal,minimal-jail'})

    def test_equal_repeated_values_agree(self):
        result, obj = self.generate('annotations {set="optional";} annotations {set="optional";}')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(obj['annotations'], {'set': 'optional'})

    def test_conflicts_fail_in_both_orders(self):
        for first, second in [('base', 'optional'), ('optional', 'base')]:
            with self.subTest(first=first):
                result, _ = self.generate('annotations {set="' + first + '";} annotations {set="' + second + '";}')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('conflicting value for set', result.stderr)

    def test_malformed_values_fail(self):
        for source in ('annotations=42;', 'annotations=false;', 'annotations {set=42;}',
                       'annotations {set="base";set="optional";}',
                       'annotations {role={admin=true;};}',
                       'annotations {set="base";} annotations=42;'):
            with self.subTest(source=source):
                result, _ = self.generate(source)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('invalid annotations', result.stderr)

    def test_subpackage_set_rewriting_preserves_other_annotations(self):
        for package, expected in [('example-dbg', 'minimal-dbg,minimal-jail-dbg'),
                                  ('example-dev', 'devel')]:
            with self.subTest(package=package):
                result, obj = self.generate('annotations {custom="opaque";} '
                    'annotations {set="minimal,minimal-jail";}', package)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(obj['annotations'], {'custom': 'opaque', 'set': expected})

    def test_switchboard_construction_belongs_to_main_package(self):
        directory = GENERATOR.parents[2] / 'packages/switchboard'
        for package, filename in [('switchboard', 'switchboard.ucl'),
                                  ('switchboard-dbg', 'common.ucl'),
                                  ('switchboard-man', 'common.ucl')]:
            with self.subTest(package=package):
                # Query bsd.pkg.mk selection so reverting the package Makefile
                # cannot leave a passing test that manually chooses common.ucl.
                selected = subprocess.check_output(['make', '-C', str(directory),
                    'REPODIR=/usr/obj/usr/src/repo', 'PKG_VERSION=1', '-V',
                    '${UCLSRC.' + package + ':U${UCLSRC}}'], text=True).strip()
                self.assertEqual(selected, filename)
                source = (directory / selected).read_text() + '\nname="5BSD-' + package + '";\n'
                result, obj = self.generate(source, package=package, raw_source=True,
                    variables=('SRCDIR', str(directory)))
                self.assertEqual(result.returncode, 0, result.stderr)
                if package != 'switchboard':
                    self.assertNotIn('5bsd.construction', obj['annotations'])
                    self.assertNotIn('scripts', obj)
                    continue
                declaration = json.loads(obj['annotations']['5bsd.construction'])
                self.assertEqual(declaration['format'], 1)
                self.assertEqual(len(declaration['actions']), 1)
                action = declaration['actions'][0]
                self.assertEqual(action['name'], 'service-identities')
                self.assertEqual(action['argv'], ['/usr/libexec/switchboard-identity-build',
                    '/etc/master.passwd', '/etc/group',
                    '/Capabilities/Config/switchboard/identities.ucl'])
                self.assertEqual(action['inputs'], ['/etc/master.passwd', '/etc/group'])
                self.assertEqual(action['outputs'], {
                    '/Capabilities/Config/switchboard/identities.ucl': {
                        'type': 'file', 'uid': 0, 'gid': 0, 'mode': 0o444,
                        'flags_set': 0, 'replace': False}})

    def test_rc_state_requirements_follow_actual_metadata_selection(self):
        directory = GENERATOR.parents[2] / 'packages/rc'
        expected = {
            ('/etc/rc.d/cleanvar', '/var/run', 'directory', 'boot'),
            ('/etc/rc.d/cleanvar', '/var/run/clean_var', 'file', 'boot'),
            ('/etc/rc.d/cleanvar', '/var/spool/lock', 'directory', 'boot'),
            ('/etc/rc.d/cleanvar', '/var/spool/lock/clean_var', 'file', 'boot'),
            ('/etc/rc.d/dmesg', '/var/run/dmesg.boot', 'file', 'boot'),
            ('/etc/rc.d/msgs', '/var/msgs/bounds', 'file', 'persistent'),
            ('/etc/rc.d/motd', '/var/run/motd', 'file', 'boot'),
            ('/etc/rc.d/motd', '/etc/motd', 'file', 'boot'),
            ('/etc/rc.d/motd', '/tmp', 'directory', 'boot'),
            ('/etc/rc.d/os-release', '/var/run/os-release', 'file', 'boot'),
            ('/etc/rc.d/os-release', '/tmp', 'directory', 'boot'),
        }
        for package in ('rc', 'rc-man', 'rc-dbg'):
            with self.subTest(package=package):
                selected = subprocess.check_output(['make', '-C', str(directory),
                    'REPODIR=/usr/obj/usr/src/repo', 'PKG_VERSION=1', '-V',
                    '${UCLSRC.' + package + ':U${UCLSRC}}'], text=True).strip()
                self.assertEqual(selected, 'rc.ucl' if package == 'rc' else 'common.ucl')
                source = (directory / selected).read_text() + '\nname="5BSD-' + package + '";\n'
                result, obj = self.generate(source, package=package, raw_source=True,
                    variables=('SRCDIR', str(directory)))
                self.assertEqual(result.returncode, 0, result.stderr)
                if package != 'rc':
                    self.assertNotIn('5bsd.state-requirements', obj['annotations'])
                    self.assertNotIn('scripts', obj)
                    continue
                rows = json.loads(obj['annotations']['5bsd.state-requirements'])['requirements']
                self.assertEqual(len(rows), len(expected))
                self.assertEqual({(r['program'], r['path'], r['type'], r['lifetime'])
                    for r in rows}, expected)
                self.assertIn('pre-install', obj['scripts'])
                self.assertIn('post-install', obj['scripts'])

    def test_runtime_recipes_follow_target_endianness(self):
        directory = GENERATOR.parents[2] / 'packages/runtime'
        source = (directory / 'runtime.ucl').read_text() + '\nname="5BSD-runtime";\n'
        for endian in ('-l', '-b'):
            with self.subTest(endian=endian):
                result, obj = self.generate(source, package='runtime', raw_source=True,
                    variables=('SRCDIR', str(directory), 'CAP_MKDB_ENDIAN', endian))
                self.assertEqual(result.returncode, 0, result.stderr)
                declaration = json.loads(obj['annotations']['5bsd.construction'])
                self.assertEqual(declaration['format'], 1)
                actions = {a['name']: a for a in declaration['actions']}
                self.assertEqual(set(actions), {'account-databases', 'service-database'})
                accounts = actions['account-databases']
                self.assertEqual(accounts['argv'], ['/usr/sbin/pwd_mkdb', '-p', '-d', '/etc', '/etc/master.passwd'])
                self.assertEqual(accounts['inputs'], ['/etc/master.passwd'])
                self.assertEqual(set(accounts['outputs']), {'/etc/passwd', '/etc/pwd.db', '/etc/spwd.db'})
                service = actions['service-database']
                self.assertEqual(service['argv'], ['/usr/sbin/services_mkdb', endian, '-q', '-o', '/var/db/services.db', '/etc/services'])
                self.assertEqual(service['inputs'], ['/etc/services'])
                self.assertEqual(set(service['outputs']), {'/var/db/services.db'})
                for action in actions.values():
                    for path, metadata in action['outputs'].items():
                        self.assertEqual(metadata, {'type': 'file', 'uid': 0, 'gid': 0,
                            'mode': 0o600 if path == '/etc/spwd.db' else 0o644,
                            'flags_set': 0, 'replace': False})

    def test_cron_pid_requirement_is_payload_specific(self):
        directory = GENERATOR.parents[2] / 'packages/cron'
        source = (directory / 'cron.ucl').read_text() + '\nname="5BSD-cron";\n'
        result, obj = self.generate(source, package='cron', raw_source=True,
            variables=('SRCDIR', str(directory)))
        self.assertEqual(result.returncode, 0, result.stderr)
        declaration = json.loads(obj['annotations']['5bsd.state-requirements'])
        self.assertEqual(declaration['format'], 1)
        self.assertEqual(len(declaration['requirements']), 3)
        rows = {r['name']: r for r in declaration['requirements']}
        self.assertEqual(set(rows), {'daemon-pid', 'job-tables-reader', 'job-tables-management'})
        for name, program in [('job-tables-reader', '/usr/sbin/cron'),
                              ('job-tables-management', '/usr/bin/crontab')]:
            self.assertEqual(rows[name]['program'], program)
            self.assertEqual(rows[name]['path'], '/var/cron/tabs')
            self.assertEqual(rows[name]['type'], 'directory')
            self.assertEqual(rows[name]['lifetime'], 'persistent')
        row = rows['daemon-pid']
        self.assertEqual(row['program'], '/usr/sbin/cron')
        self.assertEqual(row['path'], '/var/run/cron.pid')
        self.assertEqual(row['type'], 'file')
        self.assertEqual(row['lifetime'], 'boot')
        for suffix in ('man', 'dbg', 'dev'):
            common = (directory / 'common.ucl').read_text() + '\nname="5BSD-cron-' + suffix + '";\n'
            result, split = self.generate(common, package='cron-' + suffix, raw_source=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('5bsd.state-requirements', split['annotations'])

    def test_acct_state_requirements_are_payload_specific(self):
        directory = GENERATOR.parents[2] / 'packages/acct'
        source = (directory / 'acct.ucl').read_text() + '\nname="5BSD-acct";\n'
        result, obj = self.generate(source, package='acct', raw_source=True,
            variables=('SRCDIR', str(directory)))
        self.assertEqual(result.returncode, 0, result.stderr)
        declaration = json.loads(obj['annotations']['5bsd.state-requirements'])
        self.assertEqual(declaration['format'], 1)
        requirements = {r['name']: r for r in declaration['requirements']}
        self.assertEqual(set(requirements), {'active-sessions', 'last-login', 'session-history'})
        self.assertEqual(requirements['active-sessions']['path'], '/var/run/utx.active')
        self.assertEqual(requirements['active-sessions']['lifetime'], 'boot')
        for name, path in [('last-login', '/var/log/utx.lastlogin'),
                           ('session-history', '/var/log/utx.log')]:
            self.assertEqual(requirements[name]['path'], path)
            self.assertEqual(requirements[name]['lifetime'], 'persistent')
        for row in requirements.values():
            self.assertEqual(row['program'], '/usr/sbin/utx')
            self.assertEqual(row['type'], 'file')
        # The common metadata used by split packages contains no consumer claim.
        common = (directory / 'common.ucl').read_text() + '\nname="5BSD-acct-man";\n'
        result, obj = self.generate(common, package='acct-man', raw_source=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('5bsd.state-requirements', obj['annotations'])

    def test_login_accounting_state_stays_in_runtime_payload(self):
        directory = GENERATOR.parents[2] / 'packages/runtime'
        source = (directory / 'runtime.ucl').read_text() + '\nname="5BSD-runtime";\n'
        result, obj = self.generate(source, package='runtime', raw_source=True,
            variables=('SRCDIR', str(directory), 'CAP_MKDB_ENDIAN', '-l'))
        self.assertEqual(result.returncode, 0, result.stderr)
        declaration = json.loads(obj['annotations']['5bsd.state-requirements'])
        self.assertEqual(declaration['format'], 2)
        all_rows = declaration['requirements']
        rows = [r for r in all_rows if r['program'] == '/usr/bin/login']
        self.assertEqual(len(rows), 3)
        self.assertEqual({r['path']: r['lifetime'] for r in rows}, {
            '/var/run/utx.active': 'boot', '/var/log/utx.lastlogin': 'persistent',
            '/var/log/utx.log': 'persistent'})
        for row in rows:
            self.assertEqual(row['program'], '/usr/bin/login')
            self.assertEqual(row['type'], 'file')
        expected_accounts = {
            'account-public-database': ('/usr/sbin/pwd_mkdb', '/etc/pwd.db', 'file'),
            'account-secret-database': ('/usr/sbin/pwd_mkdb', '/etc/spwd.db', 'file'),
            'account-public-text': ('/usr/sbin/pwd_mkdb', '/etc/passwd', 'file'),
            'account-master-text': ('/usr/sbin/pwd_mkdb', '/etc/master.passwd', 'file'),
            'account-management-log': ('/usr/sbin/pw', '/var/log/userlog', 'file'),
            'account-group-text': ('/usr/sbin/pw', '/etc/group', 'file'),
            'account-group-workspace': ('/usr/sbin/pw', '/etc', 'directory'),
            'account-update-workspace': ('/usr/sbin/pwd_mkdb', '/etc', 'directory'),
        }
        expected_other = {
            'ordinary-loader-hints': ('/sbin/ldconfig', '/var/run/ld-elf.so.hints', 'file', 'boot'),
            'ordinary-loader-hints-workspace': ('/sbin/ldconfig', '/var/run', 'directory', 'boot'),
            'crash-dump-storage': ('/sbin/savecore', '/var/crash', 'directory', 'persistent'),
        }
        other = {r['name']: r for r in all_rows if r['program'] in ('/sbin/ldconfig', '/sbin/savecore')}
        self.assertEqual(set(other), set(expected_other))
        for name, expected in expected_other.items():
            row = other[name]
            self.assertEqual((row['program'], row['path'], row['type'], row['lifetime']), expected)
        accounts = {r['name']: r for r in all_rows
                    if r['program'] not in ('/usr/bin/login', '/sbin/ldconfig', '/sbin/savecore')}
        self.assertEqual(len(all_rows), len(rows) + len(expected_accounts) + len(expected_other))
        self.assertEqual(set(accounts), set(expected_accounts))
        for name, expected in expected_accounts.items():
            row = accounts[name]
            self.assertEqual((row['program'], row['path'], row['type']), expected)
            self.assertEqual(row['lifetime'], 'persistent')
            if row['type'] == 'directory':
                self.assertEqual(row['directory_mapping'], '/etc/accounts')
            else:
                self.assertNotIn('directory_mapping', row)
        self.assertIn('5bsd.construction', obj['annotations'])
        common = (directory / 'common.ucl').read_text() + '\nname="5BSD-runtime-man";\n'
        result, obj = self.generate(common, package='runtime-man', raw_source=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('5bsd.state-requirements', obj['annotations'])

    def test_ssh_accounting_consumer_and_subpackage_scope(self):
        directory = GENERATOR.parents[2] / 'packages/ssh'
        source = (directory / 'ssh.ucl').read_text() + '\nname="5BSD-ssh";\n'
        result, obj = self.generate(source, package='ssh', raw_source=True,
            variables=('SRCDIR', str(directory)))
        self.assertEqual(result.returncode, 0, result.stderr)
        all_rows = json.loads(obj['annotations']['5bsd.state-requirements'])['requirements']
        pid_rows = [r for r in all_rows if r['program'] == '/usr/sbin/sshd']
        self.assertEqual([(r['name'], r['path'], r['type'], r['lifetime']) for r in pid_rows],
                         [('daemon-pid', '/var/run/sshd.pid', 'file', 'boot')])
        rows = [r for r in all_rows if r['program'] != '/usr/sbin/sshd']
        self.assertEqual(len(rows), 3)
        self.assertEqual(len(all_rows), len(rows) + len(pid_rows))
        self.assertEqual({r['path']: r['lifetime'] for r in rows}, {
            '/var/run/utx.active': 'boot', '/var/log/utx.lastlogin': 'persistent',
            '/var/log/utx.log': 'persistent'})
        for row in rows:
            self.assertEqual(row['program'], '/usr/libexec/sshd-session')
            self.assertEqual(row['type'], 'file')
        for suffix in ('dbg', 'dev', 'man'):
            common = (directory / 'common.ucl').read_text() + '\nname="5BSD-ssh-' + suffix + '";\n'
            result, split = self.generate(common, package='ssh-' + suffix, raw_source=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('5bsd.state-requirements', split['annotations'])
            self.assertTrue(split['comment'].startswith(obj['comment'] + ' '))
            self.assertTrue(split['desc'].startswith(obj['desc'] + '\n\n'))

    def test_nfs_requirements_follow_sources_and_owning_package(self):
        directory = GENERATOR.parents[2] / 'packages/nfs'
        source = (directory / 'nfs.ucl').read_text() + '\nname="5BSD-nfs";\n'
        result, obj = self.generate(source, package='nfs', raw_source=True,
            variables=('SRCDIR', str(directory)))
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads(obj['annotations']['5bsd.state-requirements'])['requirements']
        expected = {
            'mountd-pid': ('mountd', '/var/run/mountd.pid', 'boot', 'mountd/pathnames.h', '_PATH_MOUNTDPID'),
            'mountd-clients': ('mountd', '/var/db/mountdtab', 'persistent', 'mountd/pathnames.h', '_PATH_RMOUNTLIST'),
            'nfsd-pid': ('nfsd', '/var/run/nfsd.pid', 'boot', 'nfsd/nfsd.c', 'DEFAULT_PIDFILE'),
            'nfsd-stable': ('nfsd', '/var/db/nfs-stablerestart', 'persistent', 'nfsd/nfsd.c', 'NFSD_STABLERESTART'),
            'nfsd-stable-backup': ('nfsd', '/var/db/nfs-stablerestart.bak', 'persistent', 'nfsd/nfsd.c', 'NFSD_STABLEBACKUP'),
            'lockd-local-socket': ('rpc.lockd', '/var/run/rpclockd.sock', 'boot', 'rpc.lockd/lockd.c', '_PATH_RPCLOCKDSOCK'),
            'statd-status': ('rpc.statd', '/var/db/statd.status', 'persistent', 'rpc.statd/statd.c', None),
        }
        self.assertEqual(set(expected), {r['name'] for r in rows})
        import re
        for row in rows:
            program, path, lifetime, filename, macro = expected[row['name']]
            self.assertEqual(row['program'], '/usr/sbin/' + program)
            self.assertEqual(row['path'], path)
            self.assertEqual(row['lifetime'], lifetime)
            self.assertEqual(row['type'], 'socket' if program == 'rpc.lockd' else 'file')
            text = (GENERATOR.parents[2] / 'usr.sbin' / filename).read_text()
            if macro:
                self.assertRegex(text, r'#define\s+' + re.escape(macro) + r'\s+"' + re.escape(path) + '"')
            else:
                self.assertIn('init_file("' + path + '")', text)
        for suffix in ('man', 'dbg', 'dev'):
            common = (directory / 'common.ucl').read_text() + '\nname="5BSD-nfs-' + suffix + '";\n'
            result, split = self.generate(common, package='nfs-' + suffix, raw_source=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('5bsd.state-requirements', split['annotations'])

    def test_capsule_immutable_template_metadata(self):
        directory = GENERATOR.parents[2] / 'packages/capsule'
        for package in ('capsule', 'capsule-dbg', 'capsule-man'):
            with self.subTest(package=package):
                selected = subprocess.check_output(['make', '-C', str(directory),
                    'REPODIR=/usr/obj/usr/src/repo', 'PKG_VERSION=1', '-V',
                    '${UCLSRC.' + package + ':U${UCLSRC}}'], text=True).strip()
                source_path = directory / selected
                if not source_path.exists():
                    source_path = GENERATOR.parent / 'ucl' / selected
                source = source_path.read_text() + '\nname="5BSD-' + package + '";\n'
                result, obj = self.generate(source, package=package, raw_source=True,
                    variables=('SRCDIR', str(directory)))
                self.assertEqual(result.returncode, 0, result.stderr)
                if package == 'capsule':
                    self.assertEqual(json.loads(obj['annotations']['5bsd.installation-templates']),
                                     {'format': 1, 'paths': ['/boot/capsule.conf']})
                else:
                    self.assertNotIn('5bsd.installation-templates', obj['annotations'])

    def test_missing_annotations_get_default(self):
        result, obj = self.generate('')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(obj['annotations'], {'set': 'base'})


if __name__ == '__main__':
    unittest.main()
