#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
from module_inventory import audit, module_description, parse_make_query, resolve_subdir


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

    def test_parallel_traversal_preserves_selection_duplicates_and_failures(self):
        with tempfile.TemporaryDirectory() as temp:
            src = Path(temp)
            modules = src / "sys/modules"
            kernel = src / "kernel"
            kernel.mkdir()
            (kernel / "opt_global.h").write_text("#define INET 1\n")
            graph = {
                ".": "a .WAIT b broken malformed missing /outside ../../escape\n\n",
                "a": "../shared\na_mod\n",
                "b": "../shared\nb_mod\n",
                "shared": "../a\nshared_mod\n",
                "broken": "",
                "malformed": "not two output lines\n",
            }
            for directory in graph:
                path = modules / directory
                path.mkdir(parents=True, exist_ok=True)
                (path / "Makefile").write_text("# query fixture\n")
            def query(command, **kwargs):
                relative = Path(command[2]).relative_to(modules).as_posix()
                self.assertIn("TARGET=arm64", command)
                self.assertIn("TARGET_ARCH=aarch64", command)
                self.assertIn("MACHINE=arm64", command)
                self.assertIn("MACHINE_ARCH=aarch64", command)
                self.assertIn("KERN_OPTS=INET", command)
                return SimpleNamespace(returncode=1 if relative == "broken" else 0,
                    stdout=graph[relative] + "arm64\naarch64\n", stderr="query failed" if relative == "broken" else "")
            with patch("module_inventory.subprocess.run", side_effect=query) as run:
                serial = audit(src, "make", "arm64", "aarch64", kernel,
                    "/dev/null", "/dev/null", "/dev/null", jobs=1)
                self.assertEqual(run.call_count, len(graph))
                run.reset_mock()
                parallel = audit(src, "make", "arm64", "aarch64", kernel,
                    "/dev/null", "/dev/null", "/dev/null", jobs=4)
                self.assertEqual(run.call_count, len(graph))
            self.assertEqual(serial.pop("query_jobs"), 1)
            self.assertEqual(parallel.pop("query_jobs"), 4)
            self.assertEqual(serial, parallel)
            self.assertEqual(parallel["status"], "incomplete")
            self.assertEqual([r["kmod"] for r in parallel["modules"]],
                ["a_mod", "b_mod", "shared_mod"])
            self.assertEqual(len(parallel["errors"]), 5)

    def test_audit_rejects_a_host_architecture_query_result(self):
        with tempfile.TemporaryDirectory() as temp:
            src = Path(temp)
            modules = src / "sys/modules"
            modules.mkdir(parents=True)
            (modules / "Makefile").write_text("# query fixture\n")
            kernel = src / "kernel"
            kernel.mkdir()
            with patch("module_inventory.subprocess.run", return_value=SimpleNamespace(
                    returncode=0, stdout="\n\namd64\namd64\n", stderr="")):
                result = audit(src, "make", "arm64", "aarch64", kernel,
                    "/dev/null", "/dev/null", "/dev/null", jobs=2)
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["selected_leaf_kmods"], 0)
            self.assertIn("differs from requested", result["errors"][0]["error"])

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
