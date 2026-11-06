# SPDX-License-Identifier: BSD-2-Clause
"""Original crypt test programs, native final links and installation contracts."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_DIRECTORY = "/usr/tests/lib/libcrypt"
_PROGRAMS = ["crypt_test", "crypt_tests"]
_CASES = {"crypt_tests": ["md5", "invalid"], "crypt_test": ["crypt_salts"]}
RUNTIME = ["//lib/libcrypt:crypt_shared", "//lib/libmd:md_shared", "//lib/atf/libatf-c:atf_c_shared", "//lib/libc:c_shared", "//lib/libsys:sys_shared"]

def crypt_tests():
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared", deps = ["//contrib/atf:c_headers"])
    cc_import(name = "crypt_interface", shared_library = "//lib/libcrypt:crypt_shared", deps = ["//lib/libcrypt:private_headers"])
    for program in _PROGRAMS:
        imported = program == "crypt_test"
        deps = [":atf_interface", ":crypt_interface"]
        if imported:
            deps += ["//lib/libnetbsd:netbsd_pie"]
        deps.append("//lib/libc:shared_abi_interface")
        bsd_link_sequence(name = program + "_link", deps = deps, target_compatible_with = _PLATFORM)
        cc_binary(name = program, srcs = ["//contrib/netbsd-tests/lib/libcrypt:t_crypt.c" if imported else "crypt_tests.c"],
            deps = [":" + program + "_link"], copts = libc_test_copts(6), defines = ["PIC"],
            linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = "install_" + program, program = program, manual = None, package = "tests", bindir = _DIRECTORY)
        for case in _CASES[program]:
            bsd_atf_test(name = "native_" + case, case_name = case, interface = "program", body = ":install_" + program + "_stripped",
                runtime_lib = RUNTIME, runner = "//tools/build/bazel:atf_runner", size = "small", timeout = "long", body_timeout_seconds = 300,
                test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, tags = ["external", "no-remote"], target_compatible_with = _PLATFORM)
    native.test_suite(name = "tests", tests = [":native_" + case for cases in _CASES.values() for case in cases], visibility = ["//visibility:public"])
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = _PROGRAMS, interfaces = {n: "atf" for n in _PROGRAMS})
    bsd_install_file(name = "install_kyuafile", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_extra", entries = [":install_kyuafile"], visibility = ["//lib/libcrypt:__pkg__"])
    bsd_install_manifest(name = "install_manifest", manifests = [":install_" + p for p in _PROGRAMS] + [":install_extra"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
