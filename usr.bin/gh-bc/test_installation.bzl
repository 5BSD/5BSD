# SPDX-License-Identifier: BSD-2-Clause
"""Maintain bc/dc fixture membership with the upstream test directory patterns."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")

def calculator_test_files():
    # Invoked in contrib/bc, so globs follow the maintained vendor tree.
    groups = [("scripts/functions.sh", "0755")]
    groups += [(path, "0755") for path in native.glob(["tests/*.py", "tests/*.sed", "tests/*.sh", "tests/*.txt"])]
    for calculator in ["bc", "dc"]:
        for subdir, mode in [("", "0444"), ("/errors", "0444"), ("/scripts", "0755")]:
            groups += [(path, mode) for path in native.glob(["tests/" + calculator + subdir + "/*.*"])]
    for path, mode in groups:
        bsd_install_file(name = "test_file_" + path.replace("/", "_"), src = path,
            destination = "/usr/tests/usr.bin/gh-bc/" + path,
            owner = "root", group = "wheel", mode = mode, install_tags = ["package=tests"])
    bsd_install_manifest(name = "test_install_manifest", entries = [":test_file_" + path.replace("/", "_") for path, mode in groups],
        visibility = ["//usr.bin/gh-bc/tests:__pkg__"])
