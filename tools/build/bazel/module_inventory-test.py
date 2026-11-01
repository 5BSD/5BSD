#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import tempfile
import unittest
from pathlib import Path
from module_inventory import module_description, parse_make_query, resolve_subdir


class ModuleInventoryTests(unittest.TestCase):
    def test_parse_make_query_preserves_empty_kmod_and_skips_wait(self):
        self.assertEqual(parse_make_query("a .WAIT b\n\n"), (["a", "b"], ""))

    def test_parse_make_query_reads_module_name(self):
        self.assertEqual(parse_make_query("\nlinuxkpi\n"), ([], "linuxkpi"))

    def test_parse_make_query_rejects_ambiguous_output(self):
        with self.assertRaisesRegex(ValueError, "exactly"):
            parse_make_query("one line\n")
        with self.assertRaisesRegex(ValueError, "one KMOD"):
            parse_make_query("\nname another\n")

    def test_resolve_sibling_subdirectory_inside_module_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "sys/modules"
            (root / "spi").mkdir(parents=True)
            (root / "spigen").mkdir()
            self.assertEqual(resolve_subdir(root, Path("spi"), "../spigen"), Path("spigen"))
            with self.assertRaisesRegex(ValueError, "escapes"):
                resolve_subdir(root, Path("spi"), "../../outside")

    def test_description_distinguishes_partial_build_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module = root / "sys/modules/example"
            module.mkdir(parents=True)
            (module / "BUILD.bazel").write_text("exports_files([\"x.c\"])\n")
            result = module_description(root, Path("example"), "example")
            self.assertTrue(result["build_file"])
            self.assertFalse(result["direct_module_macro"])
            (module / "BUILD.bazel").write_text("amd64_generic_module(module = \"example\")\n")
            self.assertTrue(module_description(root, Path("example"), "example")["direct_module_macro"])


if __name__ == "__main__":
    unittest.main()
