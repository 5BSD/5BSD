# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_awk_output.bzl", "bsd_awk_output")
load(":fixture_test.bzl", "file_fixture_test")

def file_fixtures(name):
    tests = []
    for fixture in native.glob(["tests/*.testfile"]):
        base = fixture[:-len(".testfile")]
        result = base + ".result"
        normalized = name + "_" + base.split("/")[-1] + "_result"
        bsd_awk_output(name = normalized, script = "//usr.bin/file/tests:normalize-result.awk",
            srcs = [result], output = normalized + ".result",
            awk = "@bsd_sdk//toolchain:awk", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:awk_runtime"])
        flags = native.glob([base + ".flags"], allow_empty = True)
        magic = native.glob([base + "*.magic"], allow_empty = True)
        target = name + "_" + base.split("/")[-1]
        file_fixture_test(name = target, program = "//usr.bin/file:file", fixture = fixture,
            expected = ":" + normalized, flags = flags[0] if flags else None,
            magic = magic if magic else ["//lib/libmagic:magic_compiled"],
            runtime_lib = ["//lib/libmagic:magic_shared", "//lib/libz:z_shared",
                "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"],
            runner = "//usr.bin/file/tests:fixture_runner", compare = "//tools/build/bazel:byte_compare_runner",
            size = "small")
        tests.append(":" + target)
    native.test_suite(name = name, tests = tests, visibility = ["//visibility:public"])
