# SPDX-License-Identifier: BSD-2-Clause
"""Original archive input schema/integrity contracts; no Make build is mocked."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
import install_reference_libraries as lib


class LibraryInputs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR'])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.assertTrue(self.root.is_relative_to('/usr/obj'))
        self.source = self.root / 'source'
        self.component = self.source / 'libfixture'
        self.component.mkdir(parents=True)
        self.compiler = self.root / 'compiler'
        self.compiler.write_bytes(b'compiler fixture')
        self.reference = self.root / 'reference'
        self.reference.mkdir()
        self.artifact = self.reference / 'objects' / str(self.component).lstrip('/') / 'libfixture.a'
        self.artifact.parent.mkdir(parents=True)
        self.artifact.write_bytes(b'!<arch>\n')
        self.receipt = self.reference / 'receipt.json'
        self.info = dict(format=1, status='passed', target_architecture='aarch64', component=str(self.component),
            environment=dict(compiler_selected=str(self.compiler), input_sha256={str(self.compiler): lib.digest(self.compiler)}))
        self.manifest = self.root / 'libraries.json'
        self.config = dict(format=1, libraries={'LIBSA': dict(receipt=str(self.receipt), receipt_sha256='',
            artifact=str(self.artifact.relative_to(self.reference)), artifact_sha256=lib.digest(self.artifact))})
        self.refresh()

    def refresh(self):
        self.receipt.write_text(json.dumps(self.info))
        self.config['libraries']['LIBSA']['receipt_sha256'] = lib.digest(self.receipt)
        self.manifest.write_text(json.dumps(self.config))

    def load(self):
        return lib.load(self.manifest, 'aarch64', self.source, self.compiler)

    def test_valid_exact_bindings(self):
        records, bindings = self.load()
        self.assertEqual(records['LIBSA']['artifact'], str(self.artifact))
        self.assertEqual(bindings[str(self.artifact)], lib.digest(self.artifact))
        lib.verify(bindings)

    def test_receipt_state_architecture_and_format(self):
        original = copy.deepcopy(self.info)
        for field, value in [('status', 'failed'), ('target_architecture', 'riscv64'), ('format', True)]:
            with self.subTest(field=field):
                self.info = {**original, field: value}
                self.refresh()
                with self.assertRaisesRegex(ValueError, 'must pass'):
                    self.load()

    def test_receipt_and_artifact_corruption(self):
        self.receipt.write_text(self.receipt.read_text() + ' ')
        with self.assertRaisesRegex(ValueError, 'receipt digest'):
            self.load()
        self.refresh()
        self.artifact.write_bytes(b'!<arch>\nchanged')
        with self.assertRaisesRegex(ValueError, 'artifact digest'):
            self.load()

    def test_variable_and_path_contracts(self):
        item = self.config['libraries']['LIBSA']
        self.config['libraries'] = {'CC': item}
        self.manifest.write_text(json.dumps(self.config))
        with self.assertRaisesRegex(ValueError, 'LIB variable'):
            self.load()
        self.config['libraries'] = {'LIBSA': item}
        item['artifact'] = '../elsewhere.a'
        self.manifest.write_text(json.dumps(self.config))
        with self.assertRaisesRegex(ValueError, 'canonical relative'):
            self.load()
        for value in ['/usr/obj/a b', '/usr/obj/a$bad', '/usr/obj/a;bad', '/home/foreign']:
            with self.subTest(path=value), self.assertRaises((ValueError, FileNotFoundError)):
                lib.safe_path(value, True)
        with self.assertRaisesRegex(ValueError, 'under /usr/obj'):
            lib.safe_path('/tmp', True)

    def test_component_and_compiler_identity(self):
        original = copy.deepcopy(self.info)
        self.info['component'] = str(self.root)
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'source tree'):
            self.load()
        self.info = original
        self.compiler.write_bytes(b'changed compiler')
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'compiler differs'):
            self.load()

    def test_regular_archive_and_symlink(self):
        self.artifact.write_bytes(b'!<thin>\n')
        self.config['libraries']['LIBSA']['artifact_sha256'] = lib.digest(self.artifact)
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'regular original archive'):
            self.load()
        target = self.artifact.with_name('other.a')
        target.write_bytes(b'!<arch>\n')
        self.artifact.unlink()
        self.artifact.symlink_to(target)
        self.config['libraries']['LIBSA']['artifact_sha256'] = lib.digest(target)
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'object-tree artifact'):
            self.load()

    def test_recheck_after_loading(self):
        _, bindings = self.load()
        self.artifact.write_bytes(b'!<arch>\nlate change')
        with self.assertRaisesRegex(ValueError, 'input changed'):
            lib.verify(bindings)


if __name__ == '__main__':
    unittest.main()
