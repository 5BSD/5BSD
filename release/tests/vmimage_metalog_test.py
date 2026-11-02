# SPDX-License-Identifier: BSD-2-Clause
"""The VM image METALOG gives the image root a traversable record.

A pkg(8) INSTALL_AS_USER METALOG never describes ".", and makefs(8) makes an
undescribed root directory mode 000: every unprivileged process (the
capability services run as "capability") then fails its first lookup from "/"
and dies loading /libexec/ld-elf.so.1.  metalog_normalize() in
release/tools/vmimage.subr must give the root a root:wheel 0755 record, keep
one that is given, and still sort and deduplicate.
"""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

VMIMAGE = Path(__file__).resolve().parents[1] / 'tools/vmimage.subr'
ROOT_RECORD = '. type=dir uname=root gname=wheel mode=0755'


def normalize_function():
    match = re.search(r'^metalog_normalize\(\) \{$.*?^\}$',
                      VMIMAGE.read_text(), re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError('metalog_normalize() not found in vmimage.subr')
    return match.group(0)


class ImageRoot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / 'normalize.sh').write_text(normalize_function() + '\n')
        (self.dir / 'root/bin').mkdir(parents=True)
        (self.dir / 'root/bin/f').write_text('x\n')
        self.metalog = self.dir / 'root/METALOG'
        self.metalog.write_text(
            './bin/f type=file uname=root gname=wheel mode=0555\n'
            './bin type=dir uname=root gname=wheel mode=0755\n'
            './bin type=dir uname=root gname=wheel mode=0755 tags=package=x\n')

    def tearDown(self):
        self.tmp.cleanup()

    def normalize(self):
        return subprocess.run(
            ['sh', '-c', '. ./normalize.sh; metalog_normalize root/METALOG'],
            cwd=self.dir, capture_output=True, text=True)

    def test_root_record_added_sorted_and_deduplicated(self):
        p = self.normalize()
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = p.stdout.splitlines()
        self.assertEqual(lines[0], ROOT_RECORD)
        self.assertEqual(len(lines), 3)

    @unittest.skipUnless(shutil.which('makefs') and shutil.which('fsdb'),
                         'makefs(8) and fsdb(8) are required')
    def test_makefs_root_is_searchable(self):
        p = self.normalize()
        self.assertEqual(p.returncode, 0, p.stderr)
        (self.dir / 'root/METALOG.sorted').write_text(p.stdout)
        subprocess.run(['makefs', '-t', 'ffs', '-s', '4m', '../image',
                        'METALOG.sorted'], cwd=self.dir / 'root', check=True,
                       capture_output=True)
        p = subprocess.run(['fsdb', '-r', str(self.dir / 'image')],
                           input='inode 2\n', capture_output=True, text=True)
        self.assertIn('I=2 MODE=40755 ', p.stdout)

    def test_explicit_root_record_wins_in_either_spelling(self):
        with self.metalog.open('a') as f:
            f.write('./ type=dir uname=root gname=wheel mode=0711\n')
        p = self.normalize()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.splitlines()[0],
                         '. type=dir uname=root gname=wheel mode=0711')

    def test_duplicate_non_directory_refused(self):
        with self.metalog.open('a') as f:
            f.write('./bin/f type=file uname=root gname=wheel mode=0444\n')
        p = self.normalize()
        self.assertEqual(p.returncode, 1)
        self.assertIn('duplicate non-directory', p.stderr)


if __name__ == '__main__':
    unittest.main()
