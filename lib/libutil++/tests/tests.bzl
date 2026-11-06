# SPDX-License-Identifier: BSD-2-Clause
"""Original libutil++ programs with native final ABI boundaries."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//lib/libc:test_policy.bzl", "libc_test_cxx_copts")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_DIRECTORY = "/usr/tests/lib/libutil++"
_CASES = {"stringf": ["basic", "va_list"], "up": ["FILE_up"], "pidfile": ["basic"]}
_LIBRARIES = [
    ("atf_cxx", "//lib/atf/libatf-c++:atf_cxx_shared", ["//contrib/atf:cxx_headers"]),
    ("atf_c", "//lib/atf/libatf-c:atf_c_shared", ["//contrib/atf:c_headers"]),
    ("util", "//lib/libutil:util_shared", ["//lib/libutil:headers"]),
    ("cxx", "//lib/libc++:cxx_shared", ["//lib/libc++:config_headers", "//contrib/llvm-project/libcxx/include:headers"]),
    ("cxxrt", "//lib/libcxxrt:cxxrt_shared", []),
    ("m", "//lib/msun:m_shared", []),
    ("gcc_s", "//lib/libgcc_s:gcc_s_shared", []),
]

def utilpp_tests():
    for name, label, headers in _LIBRARIES:
        cc_import(name = name + "_abi", shared_library = label, deps = headers)
    # INTERNALLIB: archive implementation only; final executable owns C++ ABI links.
    cc_import(name = "utilpp_archive", static_library = "//lib/libutil++:pie_archive", deps = ["//lib/libutil++:headers"])
    for program, cases in _CASES.items():
        deps = [":atf_cxx_abi", ":atf_c_abi", ":utilpp_archive"]
        if program == "pidfile":
            deps.append(":util_abi")
        deps += [":cxx_abi", ":cxxrt_abi", ":m_abi", ":gcc_s_abi", "//lib/libc:shared_abi_interface"]
        bsd_link_sequence(name = program + "_link", deps = deps, target_compatible_with = _PLATFORM)
        cc_binary(name = program + "_test", srcs = [program + "_test.cc"], deps = [":" + program + "_link"],
            copts = libc_test_cxx_copts(6), defines = ["PIC"], linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = "install_" + program, program = program + "_test", manual = None, package = "tests", bindir = _DIRECTORY)
        for case in cases:
            bsd_atf_test(name = program + "_" + case, body = ":install_" + program + "_stripped", case_name = case,
                interface = "program", runtime_lib = [label for name, label, _ in _LIBRARIES if name != "util" or program == "pidfile"] + ["//lib/libc:c_shared", "//lib/libsys:sys_shared"],
                runner = "//tools/build/bazel:atf_runner", test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, body_timeout_seconds = 300,
                tags = ["external", "no-remote"], size = "small", timeout = "long", target_compatible_with = _PLATFORM)
    native.test_suite(name = "tests", tests = [":" + program + "_" + case for program, cases in _CASES.items() for case in cases], visibility = ["//visibility:public"])
    names = sorted([program + "_test" for program in _CASES])
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = names, interfaces = {p: "atf" for p in names})
    bsd_install_file(name = "install_kyuafile", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = [":install_" + program for program in _CASES], entries = [":install_kyuafile"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
