# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned NetBSD libc test programs and original installation contracts."""
load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load(":test_runtime.bzl", "LIBC_TEST_RUNTIME")

_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_WARN_BEGIN = ["-Wsystem-headers", "-Werror", "-Wall", "-Wno-format-y2k"]
_WARN4 = ["-W", "-Wno-unused-parameter", "-Wstrict-prototypes", "-Wmissing-prototypes",
    "-Wpointer-arith", "-Wreturn-type", "-Wcast-qual", "-Wwrite-strings", "-Wswitch",
    "-Wshadow", "-Wunused-parameter", "-Wcast-align"]
_WARN_END = ["-Wno-uninitialized", "-Wno-pointer-sign", "-Wdate-time", "-Wno-empty-body",
    "-Wno-string-plus-int", "-Wno-unused-const-variable",
    "-Wno-error=unused-but-set-parameter", "-Wno-error=cast-function-type-mismatch"]
_WARN2 = ["-Wno-tautological-compare", "-Wno-unused-value", "-Wno-parentheses-equality",
    "-Wno-unused-function", "-Wno-enum-conversion", "-Wno-unused-local-typedef",
    "-Wno-address-of-packed-member", "-Wno-switch", "-Wno-switch-enum", "-Wno-knr-promoted-parameter"]

def netbsd_test_installation(programs, directory, warnings = 2, defines = [], libraries = {}, shared_libraries = {}, cases = {}):
    """Compile explicit source labels; preserve each suite's own library policy.

    cases is an explicit runtime subset, not the installed program inventory.
    Unlisted cases are still present in each installed original ATF program.
    """
    if warnings not in [2, 4] or not programs:
        fail("nonempty test inventory and a supported warning policy required")
    for mapping in [libraries, shared_libraries, cases]:
        if any([name not in programs for name in mapping]):
            fail("test-specific policy names an absent program")
    flags = ["-pipe", "-fno-common", "-fPIE", "-std=gnu17", "-Wno-format-zero-length"] + _WARN_BEGIN
    flags += (_WARN4 if warnings == 4 else []) + _WARN_END + (_WARN2 if warnings == 2 else []) + ["-Qunused-arguments"]
    manifests = []
    runtime_tests = []
    for program, source in programs.items():
        cc_binary(name = program, srcs = [source],
            deps = ["//lib/atf/libatf-c:atf_c", "//lib/libnetbsd:netbsd_pie",
                "//contrib/netbsd-tests:test_headers"] + libraries.get(program, []) + ["//lib/libc:shared_abi_interface"],
            dynamic_deps = ["//lib/atf/libatf-c:atf_c_shared"] + shared_libraries.get(program, []),
            copts = flags, defines = ["PIC"] + defines,
            linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None,
            package = "tests", bindir = directory)
        manifests.append(":" + program + "_install")
        for case in cases.get(program, []):
            target = program + "_" + case + "_runtime"
            bsd_atf_test(name = target, body = ":" + program, case_name = case, interface = "program",
                runtime_lib = LIBC_TEST_RUNTIME + shared_libraries.get(program, []),
                runner = "//tools/build/bazel:atf_runner", test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"},
                target_compatible_with = _PLATFORM, size = "small")
            runtime_tests.append(":" + target)
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = programs.keys(),
        interfaces = {p: "atf" for p in programs})
    bsd_install_file(name = "kyuafile_install", src = ":kyuafile", destination = directory + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = [":kyuafile_install"],
        visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = directory, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"],
        visibility = ["//visibility:public"], target_compatible_with = _PLATFORM)
    if runtime_tests:
        native.test_suite(name = "runtime_tests", tests = runtime_tests)
