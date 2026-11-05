# SPDX-License-Identifier: BSD-2-Clause
"""Original TLS programs and helper-library construction with native execution."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")

_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]

def tls_tests():
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared", deps = ["//contrib/atf:c_headers"])
    cc_import(name = "pthread_interface", shared_library = "//lib/libthr:thr_shared")
    manifests = []
    runtime_tests = []
    for stem in ["tls_dynamic", "tls_dlopen"]:
        program = stem + "_test"
        # Original helper LDADD precedes the framework/pthread libraries. Use
        # ABI imports and the existing final-consumer ordering boundary rather
        # than dynamic_deps, which places those exported library roots first.
        bsd_link_sequence(name = program + "_link", deps =
            (["//lib/libc/tests/tls_dso:link_interface"] if stem == "tls_dynamic" else []) +
            [":atf_interface", ":pthread_interface", "//lib/libnetbsd:netbsd_pie", "//lib/libc:shared_abi_interface"])
        cc_binary(name = program, srcs = ["//contrib/netbsd-tests/lib/libc/tls:t_" + stem + ".c"],
            deps = [":" + program + "_link"],
            defines = ["PIC"], copts = libc_test_copts(),
            linkopts = ["-pie", "-nodefaultlibs", "-Wl,-rpath,/usr/tests/lib/libc/tls"] + (["-Wl,-export-dynamic"] if stem == "tls_dlopen" else []),
            target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None, package = "tests", bindir = "/usr/tests/lib/libc/tls")
        manifests.append(":" + program + "_install")
        target = program + "_runtime"
        bsd_atf_test(name = target, body = ":" + program, case_name = "t_" + stem, interface = "program",
            runtime_lib = LIBC_TEST_RUNTIME + ["//lib/libthr:thr_shared", "//lib/libc/tests/tls_dso:shared", "//lib/libc/tests/tls/dso:shared"],
            runner = "//tools/build/bazel:atf_runner", test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"},
            target_compatible_with = _PLATFORM, size = "small")
        runtime_tests.append(":" + target)
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = ["tls_dlopen_test", "tls_dynamic_test"], interfaces = {p: "atf" for p in ["tls_dlopen_test", "tls_dynamic_test"]})
    bsd_install_file(name = "kyuafile_install", src = ":kyuafile", destination = "/usr/tests/lib/libc/tls/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = [":kyuafile_install"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = "/usr/tests/lib/libc/tls", manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive", "//lib/libc/tests/tls_dso:installation_archives", "//lib/libc/tests/tls/dso:installation_archives"],
        visibility = ["//visibility:public"], target_compatible_with = _PLATFORM)
    native.test_suite(name = "runtime_tests", tests = runtime_tests)
