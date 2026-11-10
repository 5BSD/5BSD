# SPDX-License-Identifier: BSD-2-Clause
"""Exercise coverage queries with real makefiles and kernel metadata separation."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2]
CHECK = SOURCE / 'release/scripts/check-world-package-coverage.sh'
FILTER = SOURCE / 'release/scripts/world-kmod-metadata.awk'


class Coverage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = self.root / 'stage with spaces'; self.stage.mkdir()
        self.packages = self.root / 'packages'; self.packages.mkdir()
        (self.packages / 'Makefile').write_text('SUBDIR= first\n.if ${EXTRA:Uno} == "yes"\nSUBDIR+= second\n.endif\n')
        for directory, names in [('first', 'alpha alpha-dev'), ('second', 'beta')]:
            p = self.packages / directory; p.mkdir()
            (p / 'Makefile').write_text('_ALLPACKAGES= ' + names + '\n')
        (self.stage / 'alpha.plist').write_text('/usr/lib/libalpha.so.1\n')

    def directory_plists(self, text):
        return subprocess.run(['awk', '-v', 'complete_dirs=yes', '-f',
            str(SOURCE / 'release/scripts/mtree-to-plist.awk')], input=text,
            cwd=self.stage, capture_output=True, text=True)

    def test_parent_directories_come_from_metadata(self):
        text = ('./usr type=dir uname=root gname=wheel mode=0755\n'
                './usr/private type=dir uname=daemon gname=wheel mode=0700\n'
                './usr/private/a type=file uname=root gname=wheel mode=0555 tags=package=alpha\n'
                './usr/private/b type=file uname=root gname=wheel mode=0555 tags=package=beta\n')
        result = self.directory_plists(text)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ('alpha', 'beta'):
            rows = (self.stage / (name + '.plist')).read_text().splitlines()
            self.assertEqual(rows.count('@dir(daemon,wheel,0700,) /usr/private'), 1)
            self.assertEqual(rows.count('@dir(root,wheel,0755,) /usr'), 1)
        self.assertFalse((self.stage / 'runtime.plist').exists())

    def test_empty_mtree_flags_and_real_flags(self):
        result = self.directory_plists(
            './usr type=dir uname=root gname=wheel mode=0755 flags=none\n'
            './usr/a type=file uname=root gname=wheel mode=0555 flags=none tags=package=alpha\n'
            './usr/b type=file uname=root gname=wheel mode=0555 flags=schg tags=package=alpha\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = (self.stage / 'alpha.plist').read_text().splitlines()
        self.assertIn('@dir(root,wheel,0755,) /usr', rows)
        self.assertIn('@(root,wheel,0555,) /usr/a', rows)
        self.assertIn('@(root,wheel,0555,schg) /usr/b', rows)

    def test_explicit_directory_not_duplicated(self):
        result = self.directory_plists(
            './usr type=dir uname=root gname=wheel mode=0755 tags=package=alpha\n'
            './usr/a type=file uname=root gname=wheel mode=0555 tags=package=alpha\n'
            './usr/b type=file uname=root gname=wheel mode=0555 tags=package=alpha\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = (self.stage / 'alpha.plist').read_text().splitlines()
        self.assertEqual(rows.count('@dir(root,wheel,0755,) /usr'), 1)

    def test_missing_parent_metadata_refused(self):
        result = self.directory_plists('./usr/bin/a type=file uname=root gname=wheel mode=0555 tags=package=alpha\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('missing complete METALOG parent', result.stderr)

    def test_conflicting_untagged_directory_refused(self):
        result = self.directory_plists(
            './usr type=dir uname=root gname=wheel mode=0755\n'
            './usr type=dir uname=root gname=wheel mode=0777\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('conflicting METALOG', result.stderr)

    def test_symlink_parent_is_not_a_directory(self):
        result = self.directory_plists(
            './usr type=link link=elsewhere\n'
            './usr/a type=file uname=root gname=wheel mode=0555 tags=package=alpha\n')
        self.assertNotEqual(result.returncode, 0)

    def test_incomplete_parent_metadata_refused(self):
        result = self.directory_plists(
            './usr type=dir mode=0755\n'
            './usr/a type=file uname=root gname=wheel mode=0555 tags=package=alpha\n')
        self.assertNotEqual(result.returncode, 0)

    def run_check(self, *variables):
        return subprocess.run(['sh', str(CHECK), str(self.stage), str(self.packages),
                               'make', *variables], capture_output=True, text=True)

    def test_active_targets(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('WORLD_PACKAGE_COVERAGE', result.stdout)

    def test_conditional_target(self):
        (self.stage / 'beta.plist').write_text('/bin/beta\n')
        self.assertNotEqual(self.run_check().returncode, 0)
        result = self.run_check('EXTRA=yes')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_old_archive_does_not_approve_missing_target(self):
        (self.stage / 'omitted.plist').write_text('/bin/omitted\n')
        (self.stage / '5BSD-omitted-1.pkg').write_text('stale archive')
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('omitted', result.stderr)

    def test_duplicate_targets(self):
        (self.packages / 'second/Makefile').write_text('_ALLPACKAGES= alpha\n')
        result = self.run_check('EXTRA=yes')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('duplicate', result.stderr)

    def test_failed_make_query(self):
        (self.packages / 'first/Makefile').write_text('.error invalid package configuration\n')
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('WORLD_PACKAGE_COVERAGE', result.stdout)

    def test_lost_make_query(self):
        """An evaluation that dies without a word still fails the check."""
        make = self.root / 'make'
        make.write_text('#!/bin/sh\ncase "$*" in\n*/first\\ *) kill -KILL $$ ;;\n'
                        'esac\nexec make "$@"\n')
        make.chmod(0o755)
        result = subprocess.run(['sh', str(CHECK), str(self.stage),
            str(self.packages), str(make)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('cannot evaluate the package makefiles', result.stderr)
        self.assertNotIn('WORLD_PACKAGE_COVERAGE', result.stdout)

    def many_directories(self):
        """More active directories than the check evaluates at once."""
        count = 2 * os.cpu_count() + 3
        names = ['many%03d' % number for number in range(count)]
        (self.packages / 'Makefile').write_text('SUBDIR= first ' + ' '.join(names) + '\n')
        for name in names:
            (self.packages / name).mkdir()
            (self.packages / name / 'Makefile').write_text('_ALLPACKAGES= ' + name + '\n')
            (self.stage / (name + '.plist')).write_text('/bin/' + name + '\n')
        return names

    def test_every_directory_is_evaluated(self):
        names = self.many_directories()
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        # Each of them is needed: without its makefile its plist is an orphan.
        for name in (names[0], names[len(names) // 2], names[-1]):
            makefile = self.packages / name / 'Makefile'
            makefile.write_text('_ALLPACKAGES=\n')
            result = self.run_check()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr.splitlines()[1:], [name])
            makefile.write_text('_ALLPACKAGES= ' + name + '\n')

    def test_one_failed_query_among_many(self):
        names = self.many_directories()
        for name in (names[0], names[len(names) // 2], names[-1]):
            makefile = self.packages / name / 'Makefile'
            makefile.write_text('.error invalid package configuration\n')
            result = self.run_check()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('cannot evaluate the package makefiles', result.stderr)
            self.assertNotIn('WORLD_PACKAGE_COVERAGE', result.stdout)
            makefile.write_text('_ALLPACKAGES= ' + name + '\n')

    def test_directories_of_a_package_not_built_here(self):
        """Directories alone, for a package the tree has but this target
        does not build, are not a payload."""
        (self.stage / 'beta.plist').write_text(
            '@dir(root,wheel,0755,) /usr/include/beta\n')
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('beta: package not built for this target', result.stderr)
        # A file is a payload.
        (self.stage / 'beta.plist').write_text(
            '@dir(root,wheel,0755,) /usr/include/beta\n/usr/include/beta/b.h\n')
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.splitlines()[1:], ['beta'])

    def test_directories_of_an_unknown_package(self):
        (self.stage / 'gamma.plist').write_text(
            '@dir(root,wheel,0755,) /usr/include/gamma\n')
        (self.stage / 'zeta.plist').write_text('/bin/zeta\n')
        (self.stage / 'aaa.plist').write_text(
            '@dir(root,wheel,0755,) /usr/include/aaa\n')
        (self.stage / 'beta.plist').write_text(
            '@dir(root,wheel,0755,) /usr/include/beta\n')
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.splitlines(), [
            'beta: package not built for this target (only @dir entries staged)',
            'staged payloads lack active world package targets:',
            'aaa', 'gamma', 'zeta'])

    def test_inactive_makefiles_are_read_only_for_directory_orphans(self):
        (self.packages / 'second/Makefile').write_text(
            '.error invalid package configuration\n')
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        # A payload orphan is refused without them, too.
        (self.stage / 'zeta.plist').write_text('/bin/zeta\n')
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.splitlines()[1:], ['zeta'])
        (self.stage / 'zeta.plist').unlink()
        # Whether directories alone are acceptable depends on them.
        (self.stage / 'beta.plist').write_text(
            '@dir(root,wheel,0755,) /usr/include/beta\n')
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('cannot evaluate the package makefiles', result.stderr)
        self.assertNotIn('WORLD_PACKAGE_COVERAGE', result.stdout)

    def test_invalid_plist_and_empty_stage(self):
        p = self.stage / 'alpha.plist'; p.unlink()
        self.assertNotEqual(self.run_check().returncode, 0)
        p.symlink_to(self.packages / 'Makefile')
        self.assertNotEqual(self.run_check().returncode, 0)

    def test_invalid_target_name(self):
        (self.packages / 'first/Makefile').write_text('_ALLPACKAGES= ../alpha\n')
        self.assertNotEqual(self.run_check().returncode, 0)

    def test_duplicate_directory_metadata_must_agree(self):
        path = self.stage / 'alpha.plist'
        path.write_text('@dir(root,wheel,0755,) /shared\n' * 2)
        self.assertEqual(self.run_check().returncode, 0)
        for second in ('@dir(root,wheel,0700,) /shared',
                       '@dir(other,wheel,0755,) /shared', '@dir /shared'):
            with self.subTest(second=second):
                path.write_text('@dir(root,wheel,0755,) /shared\n' + second + '\n')
                result = self.run_check()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('conflicting', result.stderr)
        path.write_text('@dir(root,wheel,0755,) \n')
        self.assertNotEqual(self.run_check().returncode, 0)

    def test_kernel_and_world_metadata_separation(self):
        records = [
            './boot/kernel/kernel type=file tags=package=kernel',
            './boot/kernel/core.ko type=file tags=package=kernel,debug',
            './boot/dtb/test.dtb type=file tags=package=dtb',
            './boot/kernel/untagged.ko type=file',
            './boot/kernel/owned.ko type=file tags=package=custom-module',
            './usr/lib/debug/boot/kernel/owned.ko.debug type=file tags=debug,package=custom-module']
        result = subprocess.run(['awk', '-f', str(FILTER)],
            input='\n'.join(records)+'\n', capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.splitlines(), records[-2:])

    def test_world_kernel_manuals_survive_filtering(self):
        world = './usr/share/man/man4/example.4.gz type=file uname=root gname=wheel mode=0444 tags=package=kernel,man\n'
        kernel = ('./boot/kernel/kernel type=file tags=package=kernel\n'
                  './boot/dtb/example.dtb type=file tags=package=dtb\n'
                  './boot/kernel/custom.ko type=file uname=root gname=wheel mode=0444 tags=package=custom-module\n')
        filtered = subprocess.run(['awk', '-f', str(FILTER)], input=kernel,
            capture_output=True, text=True, check=True).stdout
        subprocess.run(['awk', '-f', str(SOURCE / 'release/scripts/mtree-to-plist.awk')],
            input=world + filtered, cwd=self.stage, capture_output=True, text=True, check=True)
        self.assertTrue((self.stage / 'kernel-man.plist').is_file())
        self.assertTrue((self.stage / 'custom-module.plist').is_file())
        self.assertFalse((self.stage / 'kernel.plist').exists())
        self.assertFalse((self.stage / 'dtb.plist').exists())


    def test_fidl_manual_matches_runtime_package_selection(self):
        # Query the actual install tags and package targets. A fixed -man tag
        # silently strands this manual when manual splitting is disabled.
        for split, package in [('no', 'runtime'), ('yes', 'runtime-man')]:
            with self.subTest(split=split):
                tags = subprocess.run([
                    'make', '-C', str(SOURCE / 'share/man/man7'),
                    'NO_ROOT=yes', 'MK_MANSPLITPKG=' + split,
                    '-V', '${FIDLTAG_ARGS}'],
                    capture_output=True, text=True, check=True).stdout.strip()
                self.assertEqual(tags, '-T package=' + package)
                targets = subprocess.run([
                    'make', '-C', str(SOURCE / 'packages/runtime'),
                    'REPODIR=' + str(self.root / 'repository'),
                    'PKG_VERSION=coverage-test', 'MK_MANSPLITPKG=' + split,
                    '-V', '${_ALLPACKAGES}'],
                    capture_output=True, text=True, check=True).stdout.split()
                self.assertIn(package, targets)
                if split == 'no':
                    self.assertNotIn('runtime-man', targets)


    def test_nis_source_and_package_selection(self):
        for nis in ('no', 'yes'):
            with self.subTest(nis=nis):
                for directory, variable, name in [
                    ('bin', 'SUBDIR', 'domainname'),
                    ('share/examples', 'LDIRS', 'ypldap'),
                    ('share/examples', 'SE_DIRS', 'ypldap'),
                    ('packages', 'SUBDIR', 'yp'),
                ]:
                    result = subprocess.run([
                        'make', '-C', str(SOURCE / directory),
                        'MK_NIS=' + nis, '-V', '${' + variable + '}'],
                        capture_output=True, text=True, check=True)
                    self.assertEqual(name in result.stdout.split(), nis == 'yes',
                                     (directory, variable, nis, result.stdout))


    def test_pam_test_package_selection_matches_source(self):
        for enabled in ('yes', 'no'):
            for directory, name in [('lib/libpam', 'tests'), ('packages', 'pam-tests')]:
                result = subprocess.run(['make', '-C', str(SOURCE / directory),
                    'MK_TESTS=' + enabled, '-V', '${SUBDIR}'],
                    capture_output=True, text=True, check=True)
                self.assertEqual(name in result.stdout.split(), enabled == 'yes')
        for debug in ('yes', 'no'):
            result = subprocess.run(['make', '-C', str(SOURCE / 'packages/pam-tests'),
                'REPODIR=' + str(self.root / 'repository'), 'PKG_VERSION=coverage-test',
                'MK_DEBUG_FILES=' + debug, '-V', '${_ALLPACKAGES}', '-V', '${PKG_SETS}'],
                capture_output=True, text=True, check=True)
            words = result.stdout.split()
            self.assertIn('pam-tests', words)
            self.assertIn('tests', words)
            self.assertEqual('pam-tests-dbg' in words, debug == 'yes')

    def test_unconditional_hierarchy_has_base_package_owners(self):
        records = []
        for name, prefix in [('BSD.usr.dist', '/usr'),
                             ('BSD.debug.dist', '/usr/lib'),
                             ('BSD.include.dist', '/usr/include')]:
            output = subprocess.run([
                'mtree', '-C', '-K', 'all', '-f',
                str(SOURCE / 'etc/mtree' / name)],
                capture_output=True, text=True, check=True).stdout
            for line in output.splitlines():
                if line.startswith('./'):
                    records.append('.' + prefix + line[1:])
        subprocess.run(['awk', '-f', str(SOURCE / 'release/scripts/mtree-to-plist.awk')],
                       input='\n'.join(records) + '\n', cwd=self.stage,
                       capture_output=True, text=True, check=True)
        runtime = (self.stage / 'runtime.plist').read_text()
        for path in ['/usr/share/licenses', '/usr/libexec/lpr', '/usr/libexec/lpr/ru',
                     '/usr/share/examples/printing',
                     '/usr/lib/debug/usr/libexec/lpr',
                     '/usr/lib/debug/usr/libexec/lpr/ru']:
            self.assertIn('@dir(root,wheel,0755,) ' + path + '\n', runtime)
        self.assertIn('@dir(root,wheel,0755,) /usr/include/libmilter\n',
                      (self.stage / 'clibs-dev.plist').read_text())
        self.assertFalse((self.stage / 'lp.plist').exists())
        self.assertFalse((self.stage / 'libmilter-dev.plist').exists())


if __name__ == '__main__':
    unittest.main()
