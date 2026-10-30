# SPDX-License-Identifier: BSD-2-Clause
"""Maintained shell test layout, with explicitly declared fixture inventories."""
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_script_wrapper")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")

load(":execution.bzl", "shell_tests")

def shell_test_group(fixtures):
    root = "/usr/tests/" + native.package_name() + "/"
    # Source package includes /tests; installed hierarchy does not.
    root = root.replace("bin/sh/tests/", "bin/sh/")
    bsd_script_wrapper(name = "functional_test", body = "//bin/sh/tests:functional_test.sh",
        interpreter = "/usr/libexec/atf-sh", cat = "@bsd_sdk//toolchain:cat",
        cat_runtime = ["@bsd_sdk//toolchain:cat_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = ["functional_test"], interfaces = {"functional_test": "atf"})
    entries = []
    for source, destination, mode in [(f, f, "0444") for f in fixtures] + [
        (":functional_test", "functional_test", "0555"), (":kyuafile", "Kyuafile", "0444"),
    ]:
        name = "install_" + destination
        bsd_install_file(name = name, src = source, destination = root + destination,
            owner = "root", group = "wheel", mode = mode, install_tags = ["package=tests"])
        entries.append(":" + name)
    bsd_install_manifest(name = "install_manifest", entries = entries, visibility = ["//visibility:public"])

    shell_tests(fixtures)
