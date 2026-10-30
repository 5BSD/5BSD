# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("//tools/build/bazel:bsd_kyua_metadata.bzl", "kyua_metadata_fields")
Fields = provider(fields = ["values"])
def _probe(ctx):
    return [Fields(values = kyua_metadata_fields(ctx.attr.encoded, reserved = ctx.attr.reserved))]
probe = rule(implementation = _probe, attrs = {"encoded": attr.string(), "reserved": attr.string_list()})
def _valid(ctx):
    env = analysistest.begin(ctx)
    asserts.equals(env, ['required_user="root"', 'timeout=30', 'is_exclusive=true'], analysistest.target_under_test(env)[Fields].values)
    return analysistest.end(env)
valid_test = analysistest.make(_valid)
def _failure(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, ctx.attr.expected)
    return analysistest.end(env)
failure_test = analysistest.make(_failure, expect_failure = True, attrs = {"expected": attr.string()})
def metadata_tests(name):
    probe(name = "valid", encoded = '{"required_user":"root","timeout":30,"is_exclusive":true}', tags = ["manual"])
    valid_test(name = "valid_test", target_under_test = ":valid")
    cases = [
        ("array", "[]", [], "JSON object"),
        ("identity", '{"name":"replacement"}', [], "reserved Kyua metadata key"),
        ("injection", '{"x};os.exit(0)--":"bad"}', [], "metadata key"),
        ("nested", '{"required_user":{}}', [], "strings, integers or booleans"),
        ("null", '{"required_user":null}', [], "strings, integers or booleans"),
        ("timeout", '{"timeout":5}', ["timeout"], "reserved Kyua metadata key"),
    ]
    for case, encoded, reserved, expected in cases:
        probe(name = case, encoded = encoded, reserved = reserved, tags = ["manual"])
        failure_test(name = case + "_test", target_under_test = ":" + case, expected = expected)
    native.test_suite(name = name, tests = [":valid_test"] + [":" + case[0] + "_test" for case in cases])
