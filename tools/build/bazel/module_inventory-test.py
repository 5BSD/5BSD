#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import shutil
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
from module_inventory import audit, module_description, parse_make_query, resolve_subdir, parse_make_exports


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
                self.assertIn("SYSDIR=" + str(src / "sys"), command)
                self.assertIn("MODULE_TIED=yes", command)
                return SimpleNamespace(returncode=1 if relative == "broken" else 0,
                    stdout=graph[relative] + "arm64\naarch64\n\n", stderr="query failed" if relative == "broken" else "")
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
                    returncode=0, stdout="\n\namd64\namd64\n\n", stderr="")):
                result = audit(src, "make", "arm64", "aarch64", kernel,
                    "/dev/null", "/dev/null", "/dev/null", jobs=2)
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["selected_leaf_kmods"], 0)
            self.assertIn("differs from requested", result["errors"][0]["error"])

    def test_exports_decode_quoted_values_without_shell_execution(self):
        self.assertEqual(parse_make_exports(r"OPT_FDT=\#define\ FDT\ 1 EMPTY= X='$(do-not-execute)' X='$(do-not-execute)'"),
                         {"OPT_FDT": "#define FDT 1", "EMPTY": "", "X": "$(do-not-execute)"})
        with self.assertRaisesRegex(ValueError, "invalid exported"):
            parse_make_exports("not-an-assignment")
        with self.assertRaisesRegex(ValueError, "conflicting"):
            parse_make_exports("X=one X=two")

    def test_real_make_propagates_parent_exports_before_leaf_conditionals(self):
        make = shutil.which("make")
        if not make or subprocess.run([make, "-V", "MAKE_VERSION"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            self.skipTest("BSD Make required")
        with tempfile.TemporaryDirectory() as temp:
            src = Path(temp)
            root = src / "sys/modules"
            root.mkdir(parents=True)
            (root / "Makefile").write_text("SUBDIR=parent\nOPT_FDT=enabled\n.export OPT_FDT\n")
            parent = root / "parent"
            parent.mkdir()
            (parent / "Makefile").write_text(
                ".if !empty(OPT_FDT)\nSUBDIR=fdt\n.else\nSUBDIR=wrong\n.endif\n")
            for name in ("fdt", "wrong"):
                child = parent / name
                child.mkdir()
                (child / "Makefile").write_text("KMOD=" + name + "\n")
            kernel = src / "kernel"
            kernel.mkdir()
            result = audit(src, make, "arm64", "aarch64", kernel,
                           "/dev/null", "/dev/null", "/dev/null", jobs=2)
            self.assertEqual(result["errors"], [])
            self.assertEqual([r["kmod"] for r in result["modules"]], ["fdt"])
            self.assertIn("OPT_FDT", result["exported_make_contexts"][1]["inherited_names"])

    def test_real_make_has_source_context_before_leaf_path_expansion(self):
        make = shutil.which("make")
        if not make or subprocess.run([make, "-V", "MAKE_VERSION"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            self.skipTest("BSD Make required")
        with tempfile.TemporaryDirectory() as temp:
            src = Path(temp) / "custom-source"
            root = src / "sys/modules"
            child = root / "routing"
            child.mkdir(parents=True)
            (root / "Makefile").write_text("SUBDIR=routing\n")
            source = src / "sys/netinet"
            source.mkdir()
            (source / "route.c").write_text("/* source lookup fixture */\n")
            (child / "Makefile").write_text(
                ".PATH: ${SYSDIR}/netinet\n"
                ".if empty(.PATH:M${SYSDIR}/netinet)\n"
                ".error kernel source path was not supplied before leaf parsing\n"
                ".endif\n"
                ".if ${MODULE_TIED:Uno} != yes\n"
                ".error module query is not tied to the selected kernel\n"
                ".endif\n"
                "KMOD=routing\n")
            kernel = Path(temp) / "selected-kernel"
            kernel.mkdir()
            result = audit(src, make, "amd64", "amd64", kernel,
                           "/dev/null", "/dev/null", "/dev/null", jobs=2)
            self.assertEqual(result["errors"], [])
            self.assertEqual([r["kmod"] for r in result["modules"]], ["routing"])
            self.assertEqual(result["system_source_dir"], str(src / "sys"))
            self.assertTrue(result["module_tied"])

    def test_rejects_duplicate_directory_with_conflicting_parent_exports(self):
        with tempfile.TemporaryDirectory() as temp:
            src = Path(temp)
            for name in ("", "a", "b", "shared"):
                directory = src / "sys/modules" / name
                directory.mkdir(parents=True, exist_ok=True)
                (directory / "Makefile").touch()
            kernel = src / "kernel"
            kernel.mkdir()
            outputs = {
                ".": "a b\n\namd64\namd64\n\n",
                "a": "../shared\n\namd64\namd64\nCHOICE=one\n",
                "b": "../shared\n\namd64\namd64\nCHOICE=two\n",
                "shared": "\nshared\namd64\namd64\n\n",
            }
            def query(command, **kwargs):
                relative = Path(command[2]).relative_to(src / "sys/modules").as_posix()
                return SimpleNamespace(returncode=0, stdout=outputs[relative], stderr="")
            with patch("module_inventory.subprocess.run", side_effect=query):
                result = audit(src, "make", "amd64", "amd64", kernel,
                               "/dev/null", "/dev/null", "/dev/null", jobs=2)
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(len(result["errors"]), 1)
            self.assertIn("conflicting exported Make contexts", result["errors"][0]["error"])

    def test_leaf_policy_uses_source_make_path_and_kernel_context(self):
        make = shutil.which("make")
        if not make or subprocess.run([make, "-V", "MAKE_VERSION"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            self.skipTest("BSD Make required")
        with tempfile.TemporaryDirectory() as temp:
            src = Path(temp)
            root = src / "sys/modules"
            child = root / "selected"
            child.mkdir(parents=True)
            (root / "Makefile").write_text("SUBDIR=selected\n")
            (child / "Makefile").write_text('.include <source_policy.mk>\n')
            mk = src / "share/mk"
            mk.mkdir(parents=True)
            (mk / "sys.mk").write_text("# Minimal query-only Make fixture; no build rules.\n")
            (mk / "source_policy.mk").write_text(
                'KMOD=selected\nKMODOWN=root\nKMODGRP=wheel\nKMODMODE=0444\n'
                'KMODTAGS=package=kernel\nKMODDBGTAGS=package=kernel,dbg\n'
                'SYMLINKS=selected.ko ${KMODDIR}/alias.ko\nOBJS=second.o first.o\nBLOB_OBJS=prebuilt.o\n'
                '.if empty(KCSAN_ENABLED) || ${DEBUG_FLAGS} != "-g"\n'
                '.error selected kernel/debug context was not supplied\n.endif\n')
            kernel = src / "kernel"
            kernel.mkdir()
            (kernel / "opt_global.h").write_text("#define KCSAN 1\n")
            result = audit(src, make, "amd64", "amd64", kernel,
                           "/dev/null", "/dev/null", "/dev/null", jobs=2, leaf_policy=True)
            self.assertEqual(result["errors"], [])
            self.assertEqual(result["format"], 4)
            policy = result["modules"][0]["make_policy"]
            self.assertEqual(policy["${OBJS}"], "second.o first.o")
            self.assertEqual(policy["${BLOB_OBJS}"], "prebuilt.o")
            self.assertEqual(policy["SYMLINKS"], "selected.ko /boot/kernel/alias.ko")
            self.assertEqual(policy["KMODTAGS"], "package=kernel")
            self.assertEqual(result["kcsan_enabled"], "#define KCSAN 1")
            self.assertEqual(len(result["source_queries"]), 2)
            self.assertTrue(all(str(mk) in q["argv"] for q in result["source_queries"]))

    def test_description_distinguishes_partial_build_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module = root / "sys/modules/example"
            module.mkdir(parents=True)
            (module / "BUILD.bazel").write_text("exports_files([\"x.c\"])\n")
            result = module_description(root, Path("example"), "example")
            self.assertTrue(result["build_file"])
            self.assertFalse(result["direct_module_macro"])
            (module / "BUILD.bazel").write_text(
                'load("//tools/build/bazel:amd64_generic_module.bzl", "amd64_generic_module")\n'
                'amd64_generic_module(module = "example")\n')
            self.assertTrue(module_description(root, Path("example"), "example")["direct_module_macro"])

    def test_module_inventory_requires_matching_loaded_producer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module = root / "sys/modules/example"
            module.mkdir(parents=True)
            build = module / "BUILD.bazel"
            build.write_text('# amd64_generic_module(module = "example")\n'
                             'exports_files(["amd64_firmware_module(module = example)"])\n'
                             'load("//tools/build/bazel:amd64_generic_module.bzl", "amd64_generic_module")\n'
                             'amd64_generic_module(module = "other")\n')
            result = module_description(root, Path("example"), "example")
            self.assertTrue(result["build_file"])
            self.assertEqual(result["amd64_module_declarations"], [])
            build.write_text('load("//tools/build/bazel:amd64_firmware_module.bzl", fw = "amd64_firmware_module")\n'
                             'fw(module = "example", images = [])\n')
            result = module_description(root, Path("example"), "example")
            self.assertFalse(result["direct_module_macro"])
            self.assertEqual(result["amd64_module_declarations"],
                             [{"macro": "amd64_firmware_module", "module": "example", "line": 2}])
            build.write_text('load("//unrelated:rule.bzl", "amd64_generic_module")\n'
                             'amd64_generic_module(module = "example")\n')
            self.assertEqual(module_description(root, Path("example"), "example")["amd64_module_declarations"], [])
            build.write_text("not valid BUILD !")
            result = module_description(root, Path("example"), "example")
            self.assertEqual(result["amd64_module_declarations"], [])
            self.assertIn("parse failed", result["build_inventory_error"])


if __name__ == "__main__":
    unittest.main()
