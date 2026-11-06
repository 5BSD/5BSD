# SPDX-License-Identifier: BSD-2-Clause
"""Original generator provenance checks; fixture data does not mock a build."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
import install_reference_generators as gen

class GeneratorInputs(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"])
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.source = self.root / "source"
        self.component = self.source / "tools/generator"
        self.component.mkdir(parents=True)
        self.compiler = self.root / "compiler"
        self.compiler.write_bytes(b"compiler fixture")
        self.reference = self.root / "reference"
        self.reference.mkdir()
        self.artifact = self.reference / "objects" / str(self.component).lstrip("/") / "generator"
        self.artifact.parent.mkdir(parents=True)
        self.artifact.write_bytes(b"executable fixture")
        self.artifact.chmod(0o755)
        self.receipt = self.reference / "receipt.json"
        self.info = dict(format=1, status="passed", scope="native-amd64-Make-installation-reference",
            target_architecture="amd64", component=str(self.component),
            environment=dict(compiler_selected=str(self.compiler), input_sha256={str(self.compiler): gen.digest(self.compiler)}))
        self.manifest = self.root / "generators.json"
        self.item = dict(receipt=str(self.receipt), receipt_sha256="", artifact=str(self.artifact.relative_to(self.reference)), artifact_sha256=gen.digest(self.artifact))
        self.config = dict(format=1, generators={"MAKE_GENERATOR": self.item})
        self.refresh()
    def refresh(self):
        self.receipt.write_text(json.dumps(self.info))
        self.item["receipt_sha256"] = gen.digest(self.receipt)
        self.manifest.write_text(json.dumps(self.config))
    def load(self):
        return gen.load(self.manifest, "amd64", self.source, self.compiler)
    def test_exact_binding_and_post_load_tamper(self):
        records, bindings = self.load()
        self.assertEqual(records["MAKE_GENERATOR"]["artifact"], str(self.artifact))
        self.artifact.write_bytes(b"changed")
        with self.assertRaises(ValueError): gen.verify(bindings)
    def test_wrong_receipt_state_architecture_scope_or_compiler(self):
        original = copy.deepcopy(self.info)
        for field, value in [("status", "failed"), ("format", True), ("target_architecture", "riscv64"), ("scope", "Bazel")]:
            self.info = {**original, field: value}; self.refresh()
            with self.subTest(field=field), self.assertRaises(ValueError): self.load()
        self.info = original; self.refresh()
        self.compiler.write_bytes(b"other compiler")
        with self.assertRaises(ValueError): self.load()
    def test_source_named_generator_command(self):
        self.config["generators"] = {"JEVENTS": self.item}
        self.refresh()
        records, _ = self.load()
        self.assertEqual(records["JEVENTS"]["artifact"], str(self.artifact))
        objects = self.root / "objects"; objects.mkdir()
        (objects / "events.meta").write_text("CMD " + str(self.artifact) + " x86 arch events.c\n")
        self.assertEqual(len(gen.audit_recipes(objects, records)["JEVENTS"]), 1)

    def test_reserved_identity_environment_and_option_variables(self):
        for variable in ["CC", "CXX", "LD", "OBJTOP", "TARGET", "INSTALL", "PATH",
                         "HOME", "MAKEOBJDIR", "MAKE", "SHELL", "BUILDENV_SHELL",
                         "BTOOLSPATH", "HOST_OBJTOP", "WITH_TESTS", "WITHOUT_NIS",
                         "MK_TESTS", "generator", "BAD-NAME"]:
            self.config["generators"] = {variable: self.item}; self.refresh()
            with self.subTest(variable=variable), self.assertRaises(ValueError):
                self.load()

    def test_unsafe_variable_path_and_nonexecutable(self):
        self.config["generators"] = {"CC": self.item}; self.refresh()
        with self.assertRaises(ValueError): self.load()
        self.config["generators"] = {"MAKE_GENERATOR": self.item}
        original = self.item["artifact"]
        for value in ["../elsewhere", "/absolute", original + "/../generator"]:
            self.item["artifact"] = value; self.refresh()
            with self.subTest(path=value), self.assertRaises(ValueError): self.load()
        self.item["artifact"] = original; self.refresh(); self.artifact.chmod(0o644)
        with self.assertRaises(ValueError): self.load()
    def test_compiler_alias_binds_same_file(self):
        alias = self.compiler.with_name("cc")
        alias.symlink_to(self.compiler)
        self.info["environment"]["compiler_selected"] = str(alias)
        self.refresh()
        self.load()
    def test_receipt_and_executable_digest_mismatch(self):
        self.receipt.write_text(self.receipt.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "receipt digest"): self.load()
        self.refresh()
        self.artifact.write_bytes(b"changed executable")
        with self.assertRaisesRegex(ValueError, "artifact digest"): self.load()
    def test_recipe_must_actually_name_tool_as_command(self):
        records, _ = self.load()
        objects = self.root / "objects"; objects.mkdir()
        metadata = objects / "header.meta"
        for cmd in ["", "echo " + str(self.artifact), "wrapper " + str(self.artifact)]:
            metadata.write_text("CMD " + cmd + "\n")
            with self.subTest(command=cmd), self.assertRaises(ValueError): gen.audit_recipes(objects, records)
        metadata.write_text("CMD \nCMD " + str(self.artifact) + " > header.h\n")
        self.assertEqual(len(gen.audit_recipes(objects, records)["MAKE_GENERATOR"]), 1)

if __name__ == "__main__": unittest.main()
