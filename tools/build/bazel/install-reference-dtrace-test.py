# SPDX-License-Identifier: BSD-2-Clause
"""Runtime provenance and recipe checks; fixtures do not claim a Make build."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

import install_reference_dtrace as runtime


class RuntimeInputs(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR'])
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / 'source'
        self.component = self.source / 'cddl/lib/drti'
        self.component.mkdir(parents=True)
        self.compiler = self.root / 'compiler'
        self.compiler.write_bytes(b'compiler fixture')
        self.reference = self.root / 'reference'
        self.reference.mkdir()
        self.artifact = self.reference / 'objects' / str(self.component).lstrip('/') / 'drti.o'
        self.artifact.parent.mkdir(parents=True)
        self.artifact.write_bytes(b'\x7fELF\x02\x01' + bytes(10) + b'\x01\x00\xb7\x00')
        self.receipt = self.reference / 'receipt.json'
        self.info = dict(format=1, status='passed', scope='cross-Make-installation-reference',
            target_architecture='aarch64', component=str(self.component),
            environment=dict(compiler_selected=str(self.compiler),
                             input_sha256={str(self.compiler): runtime.digest(self.compiler)}))
        self.item = dict(receipt=str(self.receipt), receipt_sha256='',
                         artifact=str(self.artifact.relative_to(self.reference)), artifact_sha256='')
        self.config = self.root / 'runtime.json'
        self.refresh()

    def refresh(self):
        self.receipt.write_text(json.dumps(self.info))
        self.item['receipt_sha256'] = runtime.digest(self.receipt)
        self.item['artifact_sha256'] = runtime.digest(self.artifact)
        self.config.write_text(json.dumps(dict(format=1, runtime=self.item)))

    def load(self):
        return runtime.load(self.config, 'aarch64', self.source, self.compiler)

    def test_exact_binding_and_post_load_tamper(self):
        record, bindings = self.load()
        self.assertEqual(record['syslibdir'], str(self.artifact.parent))
        self.artifact.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            runtime.verify(bindings)

    def test_wrong_receipt_state_scope_architecture_or_component(self):
        original = copy.deepcopy(self.info)
        for field, value in [('format', True), ('status', 'failed'), ('scope', 'Bazel'),
                             ('target_architecture', 'amd64'), ('component', str(self.source))]:
            self.info = {**original, field: value}
            self.refresh()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load()

    def test_wrong_compiler_binding(self):
        self.info['environment']['input_sha256'][str(self.compiler)] = '0' * 64
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'compiler is not bound'):
            self.load()

    def test_changed_receipt_or_object_digest(self):
        for field in ('receipt_sha256', 'artifact_sha256'):
            self.refresh()
            self.item[field] = '0' * 64
            self.config.write_text(json.dumps(dict(format=1, runtime=self.item)))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'digest mismatch'):
                self.load()

    def test_wrong_elf_kind_machine_or_encoding(self):
        original = self.artifact.read_bytes()
        for offset, byte in [(16, 3), (18, 62), (5, 2)]:
            value = bytearray(original)
            value[offset] = byte
            self.artifact.write_bytes(value)
            self.refresh()
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, 'target ELF64'):
                self.load()

    def test_runtime_path_must_be_the_regular_original_object(self):
        outside = self.root / 'outside.o'
        self.artifact.rename(outside)
        self.artifact.symlink_to(outside)
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'regular original'):
            self.load()

    def test_recipe_audit_requires_exact_runtime_and_actual_generator(self):
        record, _ = self.load()
        objects = self.root / 'objects'
        objects.mkdir()
        metadata = objects / 'provider.o.meta'
        generator = ['/usr/obj/dtrace']
        command = generator[0] + ' -x syslibdir=' + record['syslibdir'] + ' -G -o provider.o -s provider.d input.o'
        metadata.write_text('CMD ' + command + '\n')
        self.assertEqual(len(runtime.audit_recipes(objects, record, generator)), 1)
        for bad in [command.replace('syslibdir=', 'other='),
                    command + ' -x syslibdir=/wrong', command.replace('-x syslibdir=', '-xsyslibdir='),
                    command.replace(generator[0], '/usr/obj/other')]:
            metadata.write_text('CMD ' + bad + '\n')
            with self.subTest(command=bad), self.assertRaises(ValueError):
                runtime.audit_recipes(objects, record, generator)


if __name__ == '__main__':
    unittest.main()
