# SPDX-License-Identifier: BSD-2-Clause
"""Reject unsafe or incomplete CTF path mappings in the actual merge rule."""
load("//tools/build/bazel:bsd_ctf.bzl", "bsd_ctf_merge")
load("//tools/build/bazel/tests/object_order:tests.bzl", "failure_test")


def ctf_object_path_tests():
    for name, paths, expected in [
        ("traversal", ["../first.o", "second.o"], "safe relative paths"),
        ("incomplete", ["first.o"], "complete ordered object inventory"),
        ("duplicate", ["first.o", "first.o"], "uniquely cover"),
        ("wrong_basename", ["route/other.o", "second.o"], "basename must match"),
    ]:
        bsd_ctf_merge(
            name = "paths_" + name,
            linked = ":unmerged", objects = [":regular_objects"],
            object_order = ["first.o", "second.o"], object_paths = paths,
            merger = "//cddl/usr.bin/ctfmerge:ctfmerge",
            copy_runner = "//tools/build/bazel:dtrace_copy_runner",
            output = "rejected-paths/" + name, ctf_label = "path-validation",
            enabled = False, testonly = True, tags = ["manual"],
        )
        failure_test(name = "paths_" + name + "_test",
            target_under_test = ":paths_" + name, expected = expected)
