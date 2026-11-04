# SPDX-License-Identifier: BSD-2-Clause
"""Archive epoch input contract; no stage or package identity defaults."""
load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("@bazel_skylib//rules:common_settings.bzl", "string_flag")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

def _failure(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, ctx.attr.expected)
    return analysistest.end(env)

failure_test = analysistest.make(_failure, expect_failure = True,
    attrs = {"expected": attr.string()})

def archive_epoch_tests():
    string_flag(name = "decimal_epoch", build_setting_default = "00042")
    string_flag(name = "invalid_epoch", build_setting_default = "tomorrow")
    string_flag(name = "negative_epoch", build_setting_default = "-1")
    common = dict(manifests = [":manifest"],
        directories = {"/": '{"owner":"fixture","group":"fixture","mode":"0750"}'},
        users = {"fixture": "1234"}, groups = {"fixture": "2345"},
        python = "@bsd_sdk//toolchain:extra_python",
        python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib"], testonly = True)
    bsd_install_archive(name = "decimal_epoch_archive", epoch_setting = ":decimal_epoch", **common)
    for case, attributes, message in [
        ("missing", {}, "explicit nonnegative archive epoch required"),
        ("conflict", {"epoch": 0, "epoch_setting": ":decimal_epoch"}, "either an explicit archive epoch or a setting"),
        ("invalid", {"epoch_setting": ":invalid_epoch"}, "nonnegative decimal string"),
        ("negative", {"epoch_setting": ":negative_epoch"}, "nonnegative decimal string"),
    ]:
        bsd_install_archive(name = case + "_epoch_subject", tags = ["manual"], **dict(common, **attributes))
        failure_test(name = case + "_epoch_test", target_under_test = ":" + case + "_epoch_subject", expected = message)
