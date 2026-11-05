# SPDX-License-Identifier: BSD-2-Clause
"""Original RPC test programs with declared rpcgen products and native runtime."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load("//tools/build/bazel:bsd_rpcgen.bzl", "bsd_rpcgen")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")

_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_PROGRAMS = {"rpc_test": "t_rpc.c", "xdr_test": "t_xdr.c"}
_CASES = {"xdr_test": ["xdr"], "rpc_test": ["raw", "get_svc_addr_tcp", "get_svc_addr_udp", "tcp", "udp", "tcp_poll", "udp_poll"]}

def rpc_tests():
    for output, mode in [("h_testbits.h", "-h"), ("h_testbits_xdr.c", "-c")]:
        bsd_rpcgen(name = output + "_generate", source = "//contrib/netbsd-tests/lib/libc/rpc:h_testbits.x",
            output = output, mode = mode, flags = ["-L", "-C"], cpp_flags = ["-E", "-x", "c", "-nostdinc"],
            rpcgen = "//usr.bin/rpcgen:rpcgen", cpp = "@bsd_sdk//toolchain:bin/cpp",
            compiler_inputs = "@bsd_sdk//toolchain:compile_inputs", runtime = ["@bsd_sdk//toolchain:cpp_runtime"])
    cc_library(name = "fixture_headers", hdrs = [":h_testbits.h"], strip_include_prefix = ".")
    native.filegroup(name = "generated_sources", srcs = [":h_testbits.h", ":h_testbits_xdr.c"], visibility = ["//visibility:public"])
    manifests = []
    runtime_tests = []
    for program, source in _PROGRAMS.items():
        cc_binary(name = program, srcs = ["//contrib/netbsd-tests/lib/libc/rpc:" + source] +
                ([":h_testbits_xdr.c"] if program == "xdr_test" else []),
            deps = [":fixture_headers", "//lib/atf/libatf-c:atf_c", "//lib/librpcsvc:rpcsvc",
                "//lib/libutil:util", "//lib/libnetbsd:netbsd_pie", "//lib/libc:shared_abi_interface"],
            dynamic_deps = ["//lib/atf/libatf-c:atf_c_shared", "//lib/librpcsvc:rpcsvc_shared", "//lib/libutil:util_shared"],
            copts = libc_test_copts(), defines = ["PIC"], linkopts = ["-pie", "-nodefaultlibs"],
            target_compatible_with = _PLATFORM)
        utility_installation(name = "install_" + program, program = program, manual = None,
            package = "tests", bindir = "/usr/tests/lib/libc/rpc")
        manifests.append(":install_" + program)
        # Retain labels without separate SDK-linked or rpath-modified binaries.
        native.alias(name = program + "_native", actual = ":" + program)
        for case in _CASES[program]:
            bsd_atf_test(name = "case_" + case, body = ":" + program, case_name = case, interface = "program",
                runtime_lib = LIBC_TEST_RUNTIME + ["//lib/librpcsvc:rpcsvc_shared", "//lib/libutil:util_shared"],
                runner = "//tools/build/bazel:atf_runner", test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"},
                tags = [] if case in ["raw", "xdr"] else ["manual", "requires-network"],
                size = "small", target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
            if case in ["raw", "xdr"]:
                runtime_tests.append(":case_" + case)
    native.alias(name = "xdr_objects_test", actual = ":xdr_test")
    native.alias(name = "native_xdr", actual = ":case_xdr", visibility = ["//visibility:public"])
    native.test_suite(name = "runtime_tests", tests = runtime_tests)
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = _PROGRAMS.keys(), interfaces = {p: "atf" for p in _PROGRAMS})
    bsd_install_file(name = "install_kyuafile", src = ":kyuafile", destination = "/usr/tests/lib/libc/rpc/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = [":install_kyuafile"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = "/usr/tests/lib/libc/rpc", manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
