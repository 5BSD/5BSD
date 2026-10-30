# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("@bazel_skylib//rules:common_settings.bzl", "string_flag")
load("//usr.sbin/pkg:repository.bzl", "default_repository")
load("//tools/build/bazel:bsd_install.bzl", "BsdInstallFileInfo")

def _selected(ctx):
    env = analysistest.begin(ctx)
    files = analysistest.target_under_test(env)[DefaultInfo].files.to_list()
    asserts.equals(env, 1, len(files))
    asserts.equals(env, ctx.attr.expected, files[0].basename)
    return analysistest.end(env)

_ATTRS = {"expected": attr.string(mandatory = True)}
amd64_test = analysistest.make(_selected, attrs = _ATTRS, config_settings = {"//command_line_option:platforms": "@@//usr.sbin/pkg/tests:amd64"})
i386_test = analysistest.make(_selected, attrs = _ATTRS, config_settings = {"//command_line_option:platforms": "@@//usr.sbin/pkg/tests:i386"})
arm64_test = analysistest.make(_selected, attrs = _ATTRS, config_settings = {"//command_line_option:platforms": "@@//usr.sbin/pkg/tests:arm64"})
riscv64_test = analysistest.make(_selected, attrs = _ATTRS, config_settings = {"//command_line_option:platforms": "@@//usr.sbin/pkg/tests:riscv64"})

def _failure(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, ctx.attr.expected)
    return analysistest.end(env)
failure_test = analysistest.make(_failure, expect_failure = True, attrs = _ATTRS)

def _override(ctx):
    env = analysistest.begin(ctx)
    info = analysistest.target_under_test(env)[BsdInstallFileInfo]
    asserts.equals(env, "FreeBSD.conf.quarterly", info.source.basename)
    asserts.equals(env, "/etc/pkg/FreeBSD.conf", info.metadata["destination"])
    asserts.equals(env, "0644", info.metadata["mode"])
    asserts.equals(env, ["package=pkg-bootstrap", "config"], info.metadata["tags"])
    return analysistest.end(env)
override_test = analysistest.make(_override, config_settings = {
    "@@//tools/build/bazel/config:version_branch": "",
    "@@//tools/build/bazel/config:pkg_config_branch": "",
    "@@//tools/build/bazel/config:pkg_repository_config": "@@//usr.sbin/pkg:FreeBSD.conf.quarterly",
})

def repository_tests(name):
    for machine, cpu in [("amd64", "x86_64"), ("i386", "x86_32"), ("arm64", "aarch64"), ("riscv64", "riscv64")]:
        native.platform(name = machine, constraint_values = ["@platforms//os:freebsd", "@platforms//cpu:" + cpu])
    cases = [("current", "CURRENT", ""), ("beta", "BETA2", ""), ("rc", "RC1", ""),
             ("release", "RELEASE-p3", ""), ("stable", "STABLE", ""),
             ("override", "CURRENT", "quarterly"), ("channel_only", "", "latest"),
             ("missing", "", ""), ("unknown", "CURRENT", "invalid")]
    tests = []
    for case, branch, channel in cases:
        string_flag(name = case + "_branch", build_setting_default = branch)
        string_flag(name = case + "_channel", build_setting_default = channel)
        default_repository(name = case, branch = ":" + case + "_branch", channel = ":" + case + "_channel",
            latest = "//usr.sbin/pkg:FreeBSD.conf.latest", quarterly = "//usr.sbin/pkg:FreeBSD.conf.quarterly",
            release = "//usr.sbin/pkg:FreeBSD.conf.quarterly-release", tags = ["manual"])
        if case in ["missing", "unknown"]:
            failure_test(name = case + "_test", target_under_test = ":" + case,
                expected = "requires version_branch" if case == "missing" else "unknown pkg_config_branch")
            tests.append(":" + case + "_test")
            continue
        for machine, rule in [("amd64", amd64_test), ("i386", i386_test), ("arm64", arm64_test), ("riscv64", riscv64_test)]:
            expected = "quarterly-release" if case in ["beta", "rc", "release"] else "quarterly" if case == "override" or (case == "stable" and machine == "riscv64") else "latest"
            test = case + "_" + machine
            rule(name = test, target_under_test = ":" + case, expected = "FreeBSD.conf." + expected)
            tests.append(":" + test)
    override_test(name = "file_override", target_under_test = "//usr.sbin/pkg:repository_config")
    native.test_suite(name = name, tests = tests + [":file_override"])
