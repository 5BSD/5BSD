# SPDX-License-Identifier: BSD-2-Clause
"""Original stdbit test programs, installed suite and complete ATF execution."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")

PROGRAMS = [stem + "_test" for stem in [
    "stdc_bit_ceil", "stdc_bit_floor", "stdc_bit_width", "stdc_count_ones",
    "stdc_count_zeros", "stdc_first_leading_one", "stdc_first_leading_zero",
    "stdc_first_trailing_one", "stdc_first_trailing_zero", "stdc_has_single_bit",
    "stdc_leading_ones", "stdc_leading_zeros", "stdc_trailing_ones", "stdc_trailing_zeros",
]]
_DIRECTORY = "/usr/tests/lib/libc/stdbit"
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
# Original C policy: test actual libc functions, not compiler builtins.
_COPTS = ["-pipe", "-fno-common", "-fno-builtin", "-fPIE", "-std=gnu17",
    "-Wno-format-zero-length", "-Wsystem-headers", "-Werror", "-Wall", "-Wno-format-y2k",
    "-W", "-Wno-unused-parameter", "-Wstrict-prototypes", "-Wmissing-prototypes",
    "-Wpointer-arith", "-Wreturn-type", "-Wcast-qual", "-Wwrite-strings", "-Wswitch",
    "-Wshadow", "-Wunused-parameter", "-Wcast-align", "-Wchar-subscripts",
    "-Wnested-externs", "-Wold-style-definition", "-Wno-pointer-sign", "-Wdate-time",
    "-Wmissing-variable-declarations", "-Wthread-safety", "-Wno-empty-body",
    "-Wno-string-plus-int", "-Wno-unused-const-variable",
    "-Wno-error=unused-but-set-parameter", "-Wno-error=cast-function-type-mismatch",
    "-Qunused-arguments"]

def stdbit_tests():
    # These .c files are textual dependencies, not independent translation units.
    cc_library(name = "framework", hdrs = ["stdbit-test-framework.c", "stdbit-test-kernel.c"])
    entries = []
    runtime_tests = []
    for program in PROGRAMS:
        cc_binary(name = program, srcs = [program + ".c"],
            deps = [":framework", "//lib/atf/libatf-c:atf_c", "//lib/libc:shared_abi_interface"],
            dynamic_deps = ["//lib/atf/libatf-c:atf_c_shared"],
            defines = ["PIC"], copts = _COPTS, linkopts = ["-pie", "-nodefaultlibs"],
            target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program,
            manual = None, package = "tests", bindir = _DIRECTORY)
        entries.append(":" + program + "_install")
        # Original framework instantiates each operation for these five types.
        # The ATF adapter supplies declared native runtime libraries at execution;
        # the installed programs retain their ordinary loader search policy.
        for suffix in ["uc", "us", "ui", "ul", "ull"]:
            bsd_atf_test(name = program + "_" + suffix + "_runtime",
                body = ":" + program, interface = "program",
                case_name = program[:-len("_test")] + "_" + suffix,
                runtime_lib = LIBC_TEST_RUNTIME,
                runner = "//tools/build/bazel:atf_runner",
                test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"},
                target_compatible_with = _PLATFORM, size = "small")
            runtime_tests.append(":" + program + "_" + suffix + "_runtime")
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = PROGRAMS,
        interfaces = {p: "atf" for p in PROGRAMS})
    bsd_install_file(name = "kyuafile_install", src = ":kyuafile",
        destination = _DIRECTORY + "/Kyuafile", owner = "root", group = "wheel",
        mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = entries,
        entries = [":kyuafile_install"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY,
        manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"],
        visibility = ["//visibility:public"], target_compatible_with = _PLATFORM)
    native.test_suite(name = "runtime_tests", tests = runtime_tests)
