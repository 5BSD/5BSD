# SPDX-License-Identifier: BSD-2-Clause
"""Original selected AMD64 library ATF programs and installation contracts."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import", "cc_library")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_DIRECTORY = "/usr/tests/lib/libexecinfo"
_PROGRAMS = ['backtrace_test', 'sigtramp_test']
_IMPORTED = ['backtrace_test']

# Original metadata and reviewed host selection; unselected cases remain explicit
# manual targets for disposable guests, preserving privilege/cleanup/deadlines.
_CASES = {'backtrace_test': ['backtrace_fmt_basic'], 'sigtramp_test': ['test_backtrace_sigtramp']}
_CLEANUP = {'backtrace_test': [], 'sigtramp_test': []}
_USERS = {'backtrace_test': {}, 'sigtramp_test': {}}
_TIMEOUTS = {'backtrace_test': {}, 'sigtramp_test': {}}
_HOST_CASES = {'backtrace_test': ['backtrace_fmt_basic'], 'sigtramp_test': ['test_backtrace_sigtramp']}

def library_tests():
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared", deps = ["//contrib/atf:c_headers"])
    cc_import(name = "execinfo_interface", shared_library = "//lib/libexecinfo:execinfo_shared", deps = ['//contrib/libexecinfo:headers'])
    manifests = []
    tests = []
    for program in _PROGRAMS:
        imported = program in _IMPORTED
        sources = ["//contrib/netbsd-tests/lib/libexecinfo:t_" + program.removesuffix("_test") + ".c" if imported else program + ".c"]
        deps = [":atf_interface"] + [':execinfo_interface']
        deps += (["//lib/libnetbsd:netbsd_pie", "//contrib/netbsd-tests:test_headers"] if imported else [])
        deps.append("//lib/libc:shared_abi_interface")
        bsd_link_sequence(name = program + "_link", deps = deps, target_compatible_with = _PLATFORM)
        cc_binary(name = program, srcs = sources, deps = [":" + program + "_link"],
            copts = libc_test_copts(warnings = 6), defines = ["PIC"],
            linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None,
            package = "tests", bindir = _DIRECTORY, strip_symbols = False)
        manifests.append(":" + program + "_install")
        for case in _CASES[program]:
            selected = case in _HOST_CASES[program]
            target = program + "_" + case + "_runtime"
            bsd_atf_test(name = target, body = ":" + program + "_install_stripped", case_name = case, interface = "program",
                runtime_lib = LIBC_TEST_RUNTIME + ['//lib/libexecinfo:execinfo_shared', '//lib/libelf:elf_shared', '//lib/libgcc_s:gcc_s_shared'],
                cleanup = case in _CLEANUP[program], required_user = _USERS[program].get(case, ""),
                body_timeout_seconds = _TIMEOUTS[program].get(case, 300),
                tags = ([] if selected else ["manual", "external", "no-remote"]),
                runner = "//tools/build/bazel:atf_runner", test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"},
                target_compatible_with = _PLATFORM, size = "small", timeout = "long")
            if selected:
                tests.append(":" + target)
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = sorted(_PROGRAMS), interfaces = {p: "atf" for p in _PROGRAMS})
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"],
        target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    native.test_suite(name = "runtime_tests", tests = tests)
