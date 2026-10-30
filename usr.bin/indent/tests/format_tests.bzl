# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_compare_test.bzl", "bsd_compare_test")

def format_tests():
    tests = []
    # Same numbered-fixture discovery as the maintained functional_test.sh.
    for fixture in [path for path in native.glob(["*.*"]) if len(path) >= 2 and path[-2] == "." and path[-1] in "0123456789"]:
        profile = native.glob([fixture + ".pro"], allow_empty = True)
        support = native.glob([fixture + ".list"], allow_empty = True)
        name = fixture[:-2] + "_test"
        bsd_compare_test(name = name, program = "//usr.bin/indent:indent",
            input = fixture, expected = fixture + ".stdout", expected_exit = int(fixture[-1]),
            expected_stderr = "empty.out", arguments = ["-P" + profile[0]] if profile else ["-npro"],
            working_files = {path: path for path in profile + support},
            runtime_lib = ["@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"],
            runner = "//tools/build/bazel:byte_compare_runner", size = "small")
        tests.append(":" + name)
    native.test_suite(name = "tests", tests = tests, visibility = ["//visibility:public"])
