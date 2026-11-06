# SPDX-License-Identifier: BSD-2-Clause
"""Original ATF C suites, shared helper object and installation metadata."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import", "cc_library")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_DEFINES = ['HAVE_CONFIG_H', 'ATF_BUILD_CC=\\"cc\\"', 'ATF_BUILD_CFLAGS=\\"-Wall\\"', 'ATF_BUILD_CPP=\\"cpp\\"', 'ATF_BUILD_CPPFLAGS=\\"\\"', 'ATF_BUILD_CXX=\\"c++\\"', 'ATF_BUILD_CXXFLAGS=\\"-Wall\\"', 'ATF_INCLUDEDIR=\\"/usr/include\\"']
_TOP = ['atf_c_test', 'build_test', 'check_test', 'error_test', 'macros_test', 'tc_test', 'tp_test', 'utils_test']
_DETAIL = ['dynstr_test', 'env_test', 'fs_test', 'list_test', 'map_test', 'process_test', 'sanity_test', 'text_test', 'user_test']
_HELPERS = ['process_helpers', 'version_helper']

def original_c_tests(detail = False):
    programs = _DETAIL if detail else _TOP
    helpers = _HELPERS if detail else []
    source_dir = "atf-c/detail/" if detail else "atf-c/"
    directory = "/usr/tests/lib/atf/libatf-c" + ("/detail" if detail else "")
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared", deps = ["//contrib/atf:c_test_headers"])
    if not detail:
        # Original SRCS links this helper object even when no helper is referenced.
        cc_library(name = "test_helpers", srcs = ["//contrib/atf:atf-c/detail/test_helpers.c"],
            deps = [":atf_interface", "//lib/libc:shared_abi_interface"],
            local_defines = _DEFINES, copts = libc_test_copts(3), alwayslink = True, target_compatible_with = _PLATFORM,
            visibility = ["//lib/atf/libatf-c/tests/detail:__pkg__"])
    bsd_link_sequence(name = "test_link", deps = [":atf_interface", "//lib/libc:shared_abi_interface"],
        object_groups = ["//lib/atf/libatf-c/tests:test_helpers"])
    for name in programs + helpers:
        cc_binary(name = name, srcs = ["//contrib/atf:" + source_dir + name + ".c"],
            deps = [":test_link"] if name in programs else ["//contrib/atf:c_test_headers", "//lib/libc:shared_abi_interface"],
            local_defines = _DEFINES, copts = libc_test_copts(3), linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = name + "_install", program = name, manual = None, package = "tests", bindir = directory)
    entries = []
    if not detail:
        for name in ["macros_h_test.c", "unused_test.c"]:
            target = "fixture_" + name
            bsd_install_file(name = target, src = "//contrib/atf:atf-c/" + name, destination = directory + "/" + name,
                owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
            entries.append(":" + target)
    metadata = {n: '{"required_programs":"cc"}' for n in ["atf_c_test", "build_test", "check_test", "macros_test"]} if not detail else {}
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = programs, interfaces = {n: "atf" for n in programs},
        metadata = metadata, subdirectories = [] if detail else ["detail"])
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = directory + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = [":" + n + "_install" for n in programs + helpers], entries = entries + [":kyuafile_entry"])
    bsd_test_install_archive(name = "install_archive", directory = directory, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"] + ([] if detail else ["//lib/atf/libatf-c/tests/detail:installation_archives"]),
        target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
