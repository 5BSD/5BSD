# SPDX-License-Identifier: BSD-2-Clause
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//lib/libc:test_policy.bzl", "libc_test_copts", "libc_test_cxx_copts")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_DIRECTORY = "/usr/tests/lib/libcapsicum"
_PROGRAMS = ['stream_test', 'stream_cxx_test']
# The original NO_SHARED=yes test binaries require the native unwinder too.

def library_tests():
    cc_import(name = "unwinder", static_library = "//lib/libgcc_eh:static_archive")
    for program in _PROGRAMS:
        bsd_link_sequence(name = program + "_link", deps = ["//lib/atf/libatf-c++:atf_cxx", "//lib/libcapsicum:headers", ":unwinder", "//lib/libc:static_link_objects"] if program == "stream_cxx_test" else ["//lib/atf/libatf-c:atf_c", "//lib/libcapsicum:headers", "//lib/libc:static_link_objects"], target_compatible_with = _PLATFORM)
        cc_binary(name = program, srcs = [program + (".cc" if program == "stream_cxx_test" else ".c")],
            deps = [":" + program + "_link"],
            copts = [f for f in (libc_test_cxx_copts(6) if program == "stream_cxx_test" else libc_test_copts(6)) if f != "-fPIE"],
            defines = [], linkopts = ["-nodefaultlibs", "-static"],
            features = ["fully_static_link"], linkstatic = True, target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None, package = "tests", bindir = _DIRECTORY)
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = sorted(_PROGRAMS), interfaces = {p: "atf" for p in _PROGRAMS})
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = [":" + p + "_install" for p in _PROGRAMS], entries = [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True, package = "tests")
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    _HOST_CASES = {'stream_test': ['narrow_stream', 'narrow_commands', 'ordinary_and_empty'], 'stream_cxx_test': ['narrow_commands']}
    [bsd_atf_test(name = program + "_" + case + "_runtime", body = ":" + program + "_install_stripped", case_name = case, interface = "program",
        runner = "//tools/build/bazel:atf_runner", size = "small", timeout = "long", body_timeout_seconds = 300,
        test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, tags = ["external", "no-remote"],
        runtime_lib = [],
        target_compatible_with = _PLATFORM) for program, cases in _HOST_CASES.items() for case in cases]
    native.test_suite(name = "runtime_tests", tests = [":" + program + "_" + case + "_runtime" for program, cases in _HOST_CASES.items() for case in cases])
    native.test_suite(name = "tests", tests = [":runtime_tests"], visibility = ["//visibility:public"])
    # Preserve the original public test labels while sharing installed artifacts.
    [native.alias(name = alias, actual = ":" + program + "_" + case + "_runtime") for alias, program, case in [
        ("c_narrow_stream", "stream_test", "narrow_stream"),
        ("c_narrow_commands", "stream_test", "narrow_commands"),
        ("c_ordinary_and_empty", "stream_test", "ordinary_and_empty"),
        ("cxx_narrow_commands", "stream_cxx_test", "narrow_commands"),
    ]]
