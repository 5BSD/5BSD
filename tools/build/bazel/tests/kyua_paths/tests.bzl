# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("//tools/build/bazel:bsd_kyua.bzl", "bsd_kyua_test")
def _failure(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, ctx.attr.expected)
    return analysistest.end(env)
_failure_test = analysistest.make(_failure, expect_failure = True, attrs = {"expected": attr.string()})
def path_tests(name):
    tests = []
    for case, files, expected in [
        ("parent", {":payload": "../escape"}, "normalized relative paths"),
        ("absolute", {":payload": "/escape"}, "normalized relative paths"),
        ("empty_part", {":payload": "data//x"}, "normalized relative paths"),
        ("dot", {":payload": "data/./x"}, "normalized relative paths"),
        ("nested_parent", {":payload": "data/../x"}, "normalized relative paths"),
        ("reserved", {":payload": "Kyuafile"}, "cannot overlap files"),
        ("program", {":payload": "byte_compare_runner"}, "cannot overlap files"),
        ("ancestor", {":payload": "data", ":other": "data/x"}, "cannot overlap files"),
        ("descendant", {":payload": "data/x", ":other": "data"}, "cannot overlap files"),
    ]:
        bsd_kyua_test(name = case + "_subject", program = "//tools/build/bazel:byte_compare_runner", interface = "atf",
            kyua = "@bsd_sdk//toolchain:extra_kyua", suite_files = files,
            python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
            runtime = ["@bsd_sdk//toolchain:python_stdlib"], tags = ["manual"])
        _failure_test(name = case + "_test", target_under_test = ":" + case + "_subject", expected = expected)
        tests.append(":" + case + "_test")
    native.test_suite(name = name, tests = tests)
