# SPDX-License-Identifier: BSD-2-Clause
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_DIRECTORY = "/usr/tests/lib/libcam"
_PROGRAMS = ['libcam_test', 'cam_test']

def library_tests():
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared", deps = ["//contrib/atf:c_headers"])
    cc_import(name = "cam_interface", shared_library = "//lib/libcam:cam_shared", deps = ["//lib/libcam:headers"])
    for program in _PROGRAMS:
        bsd_link_sequence(name = program + "_link", deps = [":atf_interface", ":cam_interface", "//lib/libc:shared_abi_interface"], target_compatible_with = _PLATFORM)
        cc_binary(name = program, srcs = [program + ".c"],
            deps = [":" + program + "_link"],
            copts = libc_test_copts(6),
            defines = ["PIC"], linkopts = ["-nodefaultlibs", "-pie"],
            features = [], linkstatic = True, target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None, package = "tests", bindir = _DIRECTORY)
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = sorted(_PROGRAMS), interfaces = {p: "atf" for p in _PROGRAMS})
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = [":" + p + "_install" for p in _PROGRAMS], entries = [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True, package = "tests")
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    _HOST_CASES = {'cam_test': ['cam_strmatch']}
    [bsd_atf_test(name = program + "_" + case + "_runtime", body = ":" + program + "_install_stripped", case_name = case, interface = "program",
        runner = "//tools/build/bazel:atf_runner", size = "small", timeout = "long", body_timeout_seconds = 300,
        test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, tags = ["external", "no-remote"],
        runtime_lib = ["//lib/atf/libatf-c:atf_c_shared", "//lib/libcam:cam_shared", "//lib/libsbuf:sbuf_shared", "//lib/libc:c_shared", "//lib/libsys:sys_shared"],
        target_compatible_with = _PLATFORM) for program, cases in _HOST_CASES.items() for case in cases]
    native.test_suite(name = "runtime_tests", tests = [":" + program + "_" + case + "_runtime" for program, cases in _HOST_CASES.items() for case in cases])
    native.alias(name = "cam", actual = ":cam_test_cam_strmatch_runtime")
    # libcam_test contains device/root-sensitive cases; retain all registrations for disposable-system qualification.
