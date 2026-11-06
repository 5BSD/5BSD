# SPDX-License-Identifier: BSD-2-Clause
"""Complete original ATF C++ suites and source-sharing runtime variants."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import", "cc_library")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_cxx_copts")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_COMMON_DEFINES = ['HAVE_CONFIG_H', 'ATF_INCLUDEDIR=\\"/usr/include\\"', 'ATF_C_TESTS_BASE=\\"/usr/tests/lib/atf/libatf-c\\"']
_TOP_DEFINES = ['ATF_BUILD_CXX=\\"c++\\"', 'ATF_BUILD_CXXFLAGS=\\"-Wall\\"']
_TOP = ['atf_c++_test', 'build_test', 'check_test', 'macros_test', 'tests_test', 'utils_test']
_DETAIL = ['application_test', 'env_test', 'exceptions_test', 'fs_test', 'process_test', 'text_test']
_LIBRARIES = [
    ("atf_cxx", "//lib/atf/libatf-c++:atf_cxx_shared", ["//contrib/atf:cxx_test_headers"]),
    ("atf_c", "//lib/atf/libatf-c:atf_c_shared", []),
    ("cxx", "//lib/libc++:cxx_shared", ["//contrib/llvm-project/libcxx/include:headers"]),
    ("cxxrt", "//lib/libcxxrt:cxxrt_shared", []),
    ("m", "//lib/msun:m_shared", []),
    ("gcc_s", "//lib/libgcc_s:gcc_s_shared", []),
]
RUNTIME_LIBRARIES = {"//lib/atf/libatf-c++:atf_cxx_shared": "libprivateatf-c++.so.2", "//lib/atf/libatf-c:atf_c_shared": "libprivateatf-c.so.1", "//lib/libc++:cxx_shared": "libc++.so.1", "//lib/libcxxrt:cxxrt_shared": "libcxxrt.so.1", "//lib/msun:m_shared": "libm.so.5", "//lib/libc:c_shared": "libc.so.7", "//lib/libsys:sys_shared": "libsys.so.7", "//lib/libgcc_s:gcc_s_shared": "libgcc_s.so.1"}

def original_cpp_tests(detail = False):
    programs = _DETAIL if detail else _TOP
    helpers = ["version_helper"] if detail else []
    source_dir = "atf-c++/detail/" if detail else "atf-c++/"
    directory = "/usr/tests/lib/atf/libatf-c++" + ("/detail" if detail else "")
    defines = _COMMON_DEFINES + ([] if detail else _TOP_DEFINES)
    copts = libc_test_cxx_copts(3, "gnu++20")
    for name, library, headers in _LIBRARIES:
        cc_import(name = name + "_interface", shared_library = library, deps = headers)
    deps = [":" + n + "_interface" for n, lib, headers in _LIBRARIES] + ["//lib/libc:shared_abi_interface"]
    # Each original directory has its own effective definitions. Retain direct
    # helper-object inclusion even in programs which reference none of its code.
    cc_library(name = "test_helpers", srcs = ["//contrib/atf:atf-c++/detail/test_helpers.cpp"],
        deps = deps, local_defines = defines, copts = copts, alwayslink = True, target_compatible_with = _PLATFORM)
    for name in programs + helpers:
        program_deps = deps if name in programs else [":" + n + "_interface" for n, lib, headers in _LIBRARIES if n not in ["atf_cxx", "atf_c"]] + ["//contrib/atf:cxx_test_headers", "//lib/libc:shared_abi_interface"]
        cc_library(name = name + "_objects", srcs = ["//contrib/atf:" + source_dir + name + ".cpp"],
            deps = program_deps, local_defines = defines, copts = copts, alwayslink = True, target_compatible_with = _PLATFORM)
        bsd_link_sequence(name = name + "_link", deps = program_deps,
            object_groups = [":" + name + "_objects"] + ([":test_helpers"] if name in programs else []))
        cc_binary(name = name, deps = [":" + name + "_link"], linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = name + "_install", program = name, manual = None, package = "tests", bindir = directory)
        if detail and name in ["env_test", "exceptions_test", "text_test"]:
            # Inherit the private suite search path for libc -> libsys as well.
            # Installed programs above retain no RPATH.
            cc_binary(name = name + "_runtime", deps = [":" + name + "_link"], linkopts = ["-pie", "-nodefaultlibs", "-Wl,--disable-new-dtags,-rpath,$ORIGIN"],
                target_compatible_with = _PLATFORM, visibility = ["//lib/atf/libatf-c++/tests:__pkg__"])
    entries = []
    if not detail:
        for name in ["macros_hpp_test.cpp", "unused_test.cpp"]:
            target = "fixture_" + name
            bsd_install_file(name = target, src = "//contrib/atf:atf-c++/" + name, destination = directory + "/" + name,
                owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
            entries.append(":" + target)
    metadata = {n: '{"required_programs":"c++"}' for n in ["atf_c++_test", "build_test", "check_test", "macros_test"]} if not detail else {}
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = programs, interfaces = {n: "atf" for n in programs},
        metadata = metadata, subdirectories = [] if detail else ["detail"])
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = directory + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = [":" + n + "_install" for n in programs + helpers], entries = entries + [":kyuafile_entry"])
    bsd_test_install_archive(name = "install_archive", directory = directory, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"] + ([] if detail else ["//lib/atf/libatf-c++/tests/detail:installation_archives"]),
        target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
