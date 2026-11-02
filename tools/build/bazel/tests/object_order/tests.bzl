# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts", "unittest")
load("//tools/build/bazel:bsd_object_order.bzl", "ordered_objects")


def _valid(ctx):
    env = unittest.begin(ctx)
    files = [struct(basename = "z.o"), struct(basename = "a.o")]
    asserts.equals(env, ["z.o", "a.o"], [f.basename for f in ordered_objects(files, [])])
    asserts.equals(env, ["a.o", "z.o"], [f.basename for f in ordered_objects(files, ["a.o", "z.o"])])
    return unittest.end(env)

valid_test = unittest.make(_valid)


def _subject(ctx):
    ordered_objects([struct(basename = name) for name in ctx.attr.files], ctx.attr.order)
    return []

subject = rule(implementation = _subject, attrs = {"files": attr.string_list(), "order": attr.string_list()})


def _failure(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, ctx.attr.expected)
    return analysistest.end(env)

failure_test = analysistest.make(_failure, expect_failure = True, attrs = {"expected": attr.string()})


def object_order_tests(name):
    valid_test(name = "valid_test")
    tests = [":valid_test"]
    for case, files, order, expected in [
        ("duplicate_order", ["a.o", "z.o"], ["a.o", "a.o"], "duplicate name"),
        ("missing_object", ["a.o", "z.o"], ["a.o"], "complete object inventory"),
        ("surplus_name", ["a.o"], ["a.o", "z.o"], "complete object inventory"),
        ("ambiguous_basename", ["a.o", "a.o"], ["a.o"], "ambiguous object basename"),
        ("path_order", ["a.o"], ["../a.o"], "requires basenames"),
    ]:
        subject(name = case, files = files, order = order, tags = ["manual"])
        failure_test(name = case + "_test", target_under_test = ":" + case, expected = expected)
        tests.append(":" + case + "_test")
    native.test_suite(name = name, tests = tests)
