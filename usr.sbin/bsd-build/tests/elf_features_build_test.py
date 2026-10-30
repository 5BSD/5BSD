# SPDX-License-Identifier: BSD-2-Clause
"""Build disposable programs through maintained rules; never execute them."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(os.environ.get('BSD_BUILD_SRC', '/usr/src'))
spec = importlib.util.spec_from_file_location('elf_dependencies', ROOT / 'tools/build/capimage/elf_dependencies.py')
elf = importlib.util.module_from_spec(spec); spec.loader.exec_module(elf)
ELFCTL = os.environ.get('BSD_BUILD_ELFCTL', 'elfctl')

class FeatureBuild(unittest.TestCase):
    def build(self, work, *args, success=True):
        command = ['make', '-m', str(ROOT / 'share/mk'), '-C', str(work),
                   'SRCTOP=' + str(ROOT), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
                   'ELFCTL=' + ELFCTL, 'MK_CTF=no', 'MK_MAN=no', *args]
        result = subprocess.run(command, capture_output=True, text=True)
        if success: self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else: self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def features(self, path):
        notes = elf.inspect(path.read_bytes())['freebsd_feature_control_notes']
        self.assertEqual(len(notes), 1)
        return notes[0]['value']

    def test_standard_link_paths_and_debug_splitting(self):
        for sources, debug in ((False, 'no'), (True, 'no'), (True, 'yes')):
            with self.subTest(sources=sources, debug=debug), tempfile.TemporaryDirectory(prefix='elf-feature-build-') as directory:
                work = Path(directory)
                (work / 'probe.c').write_text('int main(void) { return 0; }\n')
                (work / 'Makefile').write_text('PROG=probe\nMAN=\n' +
                    ('SRCS=probe.c\n' if sources else '') +
                    'ELF_FEATURES=wxneeded noaslr\n.include <bsd.prog.mk>\n')
                self.build(work, 'MK_DEBUG_FILES=' + debug, 'all')
                self.assertEqual(self.features(work / 'probe'), 0x09)
                if debug == 'yes':
                    self.assertEqual(self.features(work / 'probe.full'), 0x09)
                    self.assertTrue((work / 'probe.debug').is_file())
                before = (work / 'probe').stat().st_mtime_ns
                self.build(work, 'MK_DEBUG_FILES=' + debug, 'all')
                self.assertEqual((work / 'probe').stat().st_mtime_ns, before)

    def test_per_program_selection_and_install_image(self):
        with tempfile.TemporaryDirectory(prefix='elf-feature-multi-') as directory:
            work = Path(directory)
            for name in ('manager', 'ordinary'):
                (work / (name + '.c')).write_text('int main(void) { return 0; }\n')
            (work / 'Makefile').write_text('PROGS=manager ordinary\nMAN=\n'
                'ELF_FEATURES.manager=wxneeded\n.include <bsd.progs.mk>\n')
            self.build(work, 'MK_DEBUG_FILES=no', 'all')
            self.assertEqual(self.features(work / 'manager'), 0x08)
            self.assertEqual(self.features(work / 'ordinary'), 0)
        with tempfile.TemporaryDirectory(prefix='elf-feature-install-') as directory:
            work = Path(directory)
            (work / 'probe.c').write_text('int main(void) { return 0; }\n')
            (work / 'policy.json').write_text('{"test":"unsigned build input"}\n')
            (work / 'Makefile').write_text('PROG=probe\nMAN=\nELF_FEATURES=wxneeded\n'
                'CAPIMAGE_MANIFEST=policy.json\n.include <bsd.prog.mk>\n')
            self.build(work, 'MK_DEBUG_FILES=yes', 'all')
            self.assertEqual(self.features(work / 'probe.capimage.install'), 0x08)

    def test_changed_source_declaration_relinks(self):
        with tempfile.TemporaryDirectory(prefix='elf-feature-input-') as directory:
            work = Path(directory)
            (work / 'probe.c').write_text('int main(void) { return 0; }\n')
            for declaration, expected in (('', 0), ('ELF_FEATURES=wxneeded\n', 0x08), ('', 0)):
                # Exercise timestamp-based make as well as meta-mode builds.
                if (work / 'probe').exists(): time.sleep(1.1)
                (work / 'Makefile').write_text('PROG=probe\nMAN=\n' + declaration + '.include <bsd.prog.mk>\n')
                self.build(work, 'MK_DEBUG_FILES=no', 'all')
                self.assertEqual(self.features(work / 'probe'), expected)

    def test_marking_failure_is_not_a_successful_binary(self):
        with tempfile.TemporaryDirectory(prefix='elf-feature-failure-') as directory:
            work = Path(directory)
            (work / 'probe.c').write_text('int main(void) { return 0; }\n')
            (work / 'Makefile').write_text('PROG=probe\nMAN=\nELF_FEATURES=wxneeded\n.include <bsd.prog.mk>\n')
            self.build(work, 'MK_DEBUG_FILES=no', 'ELFCTL=/usr/bin/false', 'all', success=False)
            self.assertFalse((work / 'probe').exists())
            self.build(work, 'MK_DEBUG_FILES=no', 'all')
            self.assertEqual(self.features(work / 'probe'), 0x08)

if __name__ == '__main__': unittest.main()
