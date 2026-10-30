# SPDX-License-Identifier: BSD-2-Clause
"""Backend staging must track added modules and preserve measured inputs."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from fixture_stage import Fixture


class BackendStaging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backend = self.root / 'backend'; self.backend.mkdir()
        self.extra = self.root / 'extra'; self.extra.mkdir()
        self.fixture = Fixture(self.root, self.root, self.extra)

    def test_new_module_included_and_measured(self):
        for name in ('entry.py', 'new_dependency.py'):
            (self.backend / name).write_text('VALUE = 1\n')
        self.fixture.backend_python(self.backend)
        self.assertEqual({p.name for p in (self.extra/'tests').iterdir()}, {'entry.py', 'new_dependency.py'})
        for name in ('entry.py', 'new_dependency.py'):
            self.assertIn(str(self.backend / name), self.fixture.source_hashes)

    def test_empty_backend_refused(self):
        with self.assertRaisesRegex(ValueError, 'no modules'): self.fixture.backend_python(self.backend)

    def test_symlink_module_refused(self):
        (self.root/'outside').write_text('VALUE = 1\n')
        (self.backend/'alias.py').symlink_to(self.root/'outside')
        with self.assertRaisesRegex(ValueError, 'nonsymlink'): self.fixture.backend_python(self.backend)

    def test_actual_layout_reader_loads_elf_dependency(self):
        backend = Path(__file__).resolve().parents[2] / 'build/capimage'
        self.fixture.backend_python(backend)
        program = "import importlib.util; from pathlib import Path; s=importlib.util.spec_from_file_location('generation', Path(__import__('sys').argv[1])); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); e=m.elf_inspector(); assert callable(e.inspect)"
        subprocess.run(['/usr/local/bin/python3.12','-I','-S','-B','-c',program,
                        str(self.extra/'tests/generation_check.py')],check=True)


if __name__ == '__main__': unittest.main()
