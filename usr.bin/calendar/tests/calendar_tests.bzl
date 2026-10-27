# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_compare_test.bzl", "bsd_compare_test")
_RUNTIME = ["//lib/msun:m_shared", "//lib/libutil:util_shared",
    "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"]
# Native counterparts to the maintained dated regression cases.
_CASES = {
    "s1": ['-t', '29.12.2006'],
    "s2": ['-t', '30.12.2006'],
    "s3": ['-t', '31.12.2006'],
    "s4": ['-t', '01.01.2007'],
    "s5": ['-t', '21.06.2015'],
    "a1": ['-A', '3', '-t', '28.12.2006'],
    "a2": ['-A', '3', '-t', '29.12.2006'],
    "a3": ['-A', '3', '-t', '30.12.2006'],
    "a4": ['-A', '3', '-t', '31.12.2006'],
    "a5": ['-A', '3', '-t', '01.01.2007'],
    "b1": ['-B', '3', '-t', '31.12.2006'],
    "b2": ['-B', '3', '-t', '01.01.2007'],
    "b3": ['-B', '3', '-t', '02.01.2007'],
    "b4": ['-B', '3', '-t', '03.01.2007'],
    "b5": ['-B', '3', '-t', '04.01.2007'],
    "w0-1": ['-W', '0', '-t', '28.12.2006'],
    "w0-2": ['-W', '0', '-t', '29.12.2006'],
    "w0-3": ['-W', '0', '-t', '30.12.2006'],
    "w0-4": ['-W', '0', '-t', '31.12.2006'],
    "w0-5": ['-W', '0', '-t', '01.01.2007'],
    "w0-6": ['-W', '0', '-t', '02.01.2007'],
    "w0-7": ['-W', '0', '-t', '03.01.2007'],
    "wn-1": ['-W', '0', '-t', '28.12.2006'],
    "wn-2": ['-W', '1', '-t', '28.12.2006'],
    "wn-3": ['-W', '2', '-t', '28.12.2006'],
    "wn-4": ['-W', '3', '-t', '28.12.2006'],
    "wn-5": ['-W', '4', '-t', '28.12.2006'],
    "wn-6": ['-W', '5', '-t', '28.12.2006'],
    "wn-7": ['-W', '6', '-t', '28.12.2006'],
}
def calendar_tests():
    for name, arguments in _CASES.items():
        bsd_compare_test(name = name + "_test", program = "//usr.bin/calendar:calendar",
            arguments = arguments + ["-f"], file_arguments = ["calendar.calibrate"],
            expected = "regress." + name + ".out", expected_stderr = "empty.out",
            environment = {"TZ": "UTC"}, runtime_lib = _RUNTIME,
            runner = "//tools/build/bazel:byte_compare_runner", size = "small")
    for name in ["comment", "cond"]:
        bsd_compare_test(name = name + "_test", program = "//usr.bin/calendar:calendar",
            arguments = ["-t", "01.01.2020", "-A", "30", "-f"], file_arguments = ["calendar." + name],
            expected = "regress." + name + ".out", expected_stderr = "empty.out",
            environment = {"TZ": "UTC"}, runtime_lib = _RUNTIME,
            runner = "//tools/build/bazel:byte_compare_runner", size = "small")
    native.test_suite(name = "tests", tests = [":" + name + "_test" for name in _CASES] + [":comment_test", ":cond_test"], visibility = ["//visibility:public"])
