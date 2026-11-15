# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the release media package selection with a package-command fixture."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2]
STAGE = SOURCE / 'release/scripts/pkgbase-stage.lua'
CATALOGUE = ['pkg', '5BSD-set-minimal', '5BSD-set-base', '5BSD-set-base-dbg',
             '5BSD-set-base-jail', '5BSD-set-lib32', '5BSD-set-lib32-dbg',
             '5BSD-set-src', '5BSD-set-tests', '5BSD-kernel-man', '5BSD-runtime']
PKG = '''#!/bin/sh
case " $* " in
*' rquery '*) cat "$TEST_CATALOGUE" ;;
*' fetch '*) printf '%s\\n' "$*" > "$TEST_FETCH" ;;
esac
exit 0
'''


class Stage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pkg = self.root / 'pkg'
        self.pkg.write_text(PKG)
        self.pkg.chmod(0o755)

    def stage(self, kernels, kernel=None, media='disc', inherited=None):
        """Return the result and the packages fetched for the media."""
        fetch = self.root / 'fetch'
        fetch.unlink(missing_ok=True)
        (self.root / 'catalogue').write_text(
            ''.join(name + '\n' for name in CATALOGUE + kernels))
        env = dict(os.environ, PKG_CMD=str(self.pkg),
                   TEST_CATALOGUE=str(self.root / 'catalogue'),
                   TEST_FETCH=str(fetch))
        env.pop('MEDIA_KERNEL', None)
        env.pop('PKG_NAME_PREFIX', None)
        if kernel is not None:
            env['MEDIA_KERNEL'] = kernel
        result = subprocess.run(['/usr/libexec/flua', str(STAGE), media,
            str(self.root / 'repos'), str(self.root / 'offline'), '32',
            'FreeBSD:16:amd64', str(self.root / 'pkgdb')], env=env,
            capture_output=True, text=True)
        if not fetch.exists():
            return result, None
        words = fetch.read_text().split()
        return result, words[words.index(str(self.root / 'offline')) + 1:]

    def refused(self, message, *arguments, **keywords):
        result, fetched = self.stage(*arguments, **keywords)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertIsNone(fetched)

    def test_only_kernel_is_found(self):
        for kernel in (None, ''):
            result, fetched = self.stage(
                ['5BSD-kernel-generic-nodebug', '5BSD-kernel-generic-nodebug-dbg'],
                kernel)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(fetched, ['pkg', '5BSD-set-base',
                '5BSD-set-base-jail', '5BSD-kernel-generic-nodebug',
                '5BSD-kernel-generic-nodebug-dbg', '5BSD-set-src',
                '5BSD-set-tests', '5BSD-set-lib32'])

    def test_dvd_carries_debug_sets(self):
        result, fetched = self.stage(['5BSD-kernel-generic'], media='dvd')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fetched, ['pkg', '5BSD-set-base', '5BSD-set-base-dbg',
            '5BSD-set-base-jail', '5BSD-kernel-generic', '5BSD-set-src',
            '5BSD-set-tests', '5BSD-set-lib32', '5BSD-set-lib32-dbg'])

    def test_several_kernels_need_a_choice(self):
        kernels = ['5BSD-kernel-generic', '5BSD-kernel-generic-dbg',
                   '5BSD-kernel-generic-nodebug',
                   '5BSD-kernel-generic-nodebug-dbg', '5BSD-kernel-custom-debug']
        self.refused('more than one kernel; set KERNCONF', kernels)
        self.refused('more than one kernel; set KERNCONF', kernels, '')
        for kernel, package, debug in (
                ('GENERIC', '5BSD-kernel-generic', True),
                ('GENERIC-NODEBUG', '5BSD-kernel-generic-nodebug', True),
                ('CUSTOM_DEBUG', '5BSD-kernel-custom-debug', False)):
            result, fetched = self.stage(kernels, kernel)
            self.assertEqual(result.returncode, 0, result.stderr)
            chosen = [name for name in fetched if '-kernel-' in name]
            self.assertEqual(chosen,
                [package, package + '-dbg'] if debug else [package])

    def test_missing_kernel(self):
        self.refused('repository has no kernel package\n', [])
        self.refused('no kernel package 5BSD-kernel-custom',
            ['5BSD-kernel-generic', '5BSD-kernel-custom-debug'], 'CUSTOM')
        # Debug symbols and manuals are not kernels, even when named.
        self.refused('no kernel package 5BSD-kernel-generic-dbg',
            ['5BSD-kernel-generic', '5BSD-kernel-generic-dbg'], 'GENERIC-DBG')
        self.refused('no kernel package 5BSD-kernel-man',
            ['5BSD-kernel-generic'], 'MAN')

    def test_invalid_name(self):
        for kernel in ('GENERIC NODEBUG', 'GENERIC;id', '$(id)', 'a/b', ' '):
            self.refused('invalid MEDIA_KERNEL', ['5BSD-kernel-generic'], kernel)

    def test_makefile_names_the_kernel(self):
        """The media rules always say which kernel, from KERNCONF alone."""
        lines = (SOURCE / 'release/Makefile').read_text().splitlines()
        calls = [number for number, line in enumerate(lines)
                 if re.search(r'scripts/pkgbase-stage\.lua (disc|dvd) ', line)]
        self.assertEqual(len(calls), 2)
        for number in calls:
            self.assertEqual(lines[number - 1], '\tenv PKG_CMD=${PKG_CMD:Q} '
                'MEDIA_KERNEL=${KERNCONF:U:[1]:Q} \\')
        makefile = self.root / 'Makefile'
        makefile.write_text('all:\n\t@env MEDIA_KERNEL=${KERNCONF:U:[1]:Q} '
            'sh -c \'printf "%s\\n" "$$MEDIA_KERNEL"\'\n')
        for arguments, expected in (([], ''), (['KERNCONF='], ''),
                (['KERNCONF=GENERIC-NODEBUG'], 'GENERIC-NODEBUG'),
                (['KERNCONF=CUSTOM_DEBUG GENERIC'], 'CUSTOM_DEBUG')):
            env = dict(os.environ, MEDIA_KERNEL='INHERITED')
            env.pop('KERNCONF', None)
            for name in ('MAKEFLAGS', 'MAKELEVEL', 'MAKEOBJDIRPREFIX'):
                env.pop(name, None)
            output = subprocess.check_output(['make', '-f', str(makefile)]
                + arguments, cwd=self.root, env=env, text=True)
            self.assertEqual(output, expected + '\n')

    def test_producer_spells_the_package_as_selected(self):
        """Makefile.inc1 names kernel packages as this script and bsdinstall
        look for them: lower case, a hyphen for each underscore."""
        text = (SOURCE / 'Makefile.inc1').read_text()
        names = re.findall(r'PKGNAME "kernel-(\$\{[^}]*\})\$\{flavor\}"', text)
        self.assertEqual(names, ['${INSTALLKERNEL:tl:S/_/-/g}',
                                 '${_kernel:tl:S/_/-/g}'])
        makefile = self.root / 'Makefile'
        makefile.write_text('all:\n\t@echo ' + ' '.join(names) + '\n')
        output = subprocess.check_output(['make', '-f', str(makefile),
            'INSTALLKERNEL=CUSTOM_DEBUG', '_kernel=Other_Kernel-X'],
            cwd=self.root, text=True)
        self.assertEqual(output, 'custom-debug other-kernel-x\n')
        result, fetched = self.stage(['5BSD-kernel-' + output.split()[0]],
                                     'CUSTOM_DEBUG')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('5BSD-kernel-custom-debug', fetched)


if __name__ == '__main__':
    unittest.main()
