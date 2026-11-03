# SPDX-License-Identifier: BSD-2-Clause
"""Native declarations for Make-selected base Googletest self-test programs."""
load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//tools/build/bazel:bsd_program_test.bzl", "bsd_program_test")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_strip_binary")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")

_RUNTIME = ["//lib/libc:c_shared", "//lib/libsys:sys_shared",
    "//lib/libc++:cxx_shared", "//lib/libcxxrt:cxxrt_shared", "//lib/msun:m_shared",
    "//lib/libthr:thr_shared", "//lib/libregex:regex_shared",
    "@bsd_sdk//toolchain:sysroot/lib/libgcc_s.so.1"]

def selftest_program(name, srcs, component, warnings = [], pthread = False):
    frameworks = {"gtest": ["gtest"], "gtest_main": ["gtest_main", "gtest"],
        "gmock": ["gmock", "gtest"], "gmock_main": ["gmock_main", "gmock", "gtest"]}[component]
    libraries = ["//lib/googletest/" + item + ":" + item for item in frameworks]
    shared = [library + "_shared" for library in libraries]
    cc_binary(name = name, srcs = srcs,
        deps = ["//contrib/googletest:bsd_selftest_include_roots",
            "//lib/libc++:cxx", "//lib/libcxxrt:cxxrt", "//lib/msun:m"] +
            libraries + (["//lib/libthr:thr"] if pthread else []),
        dynamic_deps = shared + ["//lib/libc++:cxx_shared", "//lib/libcxxrt:cxxrt_shared", "//lib/msun:m_shared"] +
            (["//lib/libthr:thr_shared"] if pthread else []),
        local_defines = ["GTEST_HAS_POSIX_RE=1", "GTEST_HAS_PTHREAD=1", "GTEST_HAS_STREAM_REDIRECTION=1"],
        # tests/Makefile.inc chooses -O0 and -g0 for the default empty DEBUG_FLAGS.
        copts = ["-O0", "-g0", "-fPIE", "-nostdinc++", "-std=gnu++17", "-frtti",
            "-Wno-deprecated-copy", "-Wno-character-conversion"] + warnings,
        linkopts = ["-pie"] + (["-pthread"] if pthread else []),
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"],
        visibility = ["//visibility:public"])
    bsd_program_test(name = name + "_test", program = ":" + name, interface = "plain",
        runtime_lib = _RUNTIME + shared, runner = "//tools/build/bazel:program_test_runner", size = "medium",
        visibility = ["//visibility:public"])

def selftest_installation(programs, component):
    directory = "/usr/tests/lib/googletest/" + component
    entries = []
    for program in programs:
        bsd_strip_binary(name = program + "_stripped", src = ":" + program,
            output = "installed/" + program, strip = "@bsd_sdk//toolchain:bin/llvm-strip",
            strip_inputs = "@bsd_sdk//toolchain:llvm-strip_runtime")
        bsd_install_file(name = "install_" + program, src = ":" + program + "_stripped",
            destination = directory + "/" + program, owner = "root", group = "wheel",
            mode = "0555", install_tags = ["package=tests"])
        entries.append(":install_" + program)
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = sorted(programs),
        interfaces = {name: "plain" for name in programs})
    bsd_install_file(name = "install_kyuafile", src = ":kyuafile",
        destination = directory + "/Kyuafile", owner = "root", group = "wheel",
        mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", entries = entries + [":install_kyuafile"],
        visibility = ["//visibility:public"])
