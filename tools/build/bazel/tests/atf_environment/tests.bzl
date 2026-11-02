# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
def _failure(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, ctx.attr.expected)
    return analysistest.end(env)
_failure_test = analysistest.make(_failure, expect_failure = True, attrs = {"expected": attr.string()})
def environment_tests(name):
    tests = []
    for case, key, expected in [
        ("protocol", "BSD_ATF_CASE", "reserved ATF environment"),
        ("config", "BSD_ATF_CONFIG_NAME_0", "reserved ATF environment"),
        ("xml", "XML_OUTPUT_FILE", "reserved ATF environment"),
        ("temporary", "TEST_TMPDIR", "reserved ATF environment"),
        ("runfiles", "RUNFILES_DIR", "reserved ATF environment"),
        ("path", "PATH", "reserved ATF environment"),
        ("loader", "LD_LIBRARY_PATH", "reserved ATF environment"),
        ("locale", "LC_ALL", "reserved ATF environment"),
        ("empty", "", "invalid ATF environment"),
        ("digit", "1_BAD", "invalid ATF environment"),
        ("equals", "A=B", "invalid ATF environment"),
    ]:
        bsd_atf_test(name = case + "_subject", body = ":startup", case_name = "alpha", interface = "program",
            runner = "//tools/build/bazel:atf_runner", test_environment = {key: "override"}, tags = ["manual"])
        _failure_test(name = case + "_test", target_under_test = ":" + case + "_subject", expected = expected)
        tests.append(":" + case + "_test")
    native.test_suite(name = name, tests = tests + [":startup_alpha", ":startup_beta"])
