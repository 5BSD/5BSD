# SPDX-License-Identifier: BSD-2-Clause
"""Original resolver programs and VNET shell fixture installation."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_script_wrapper")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_DIRECTORY = "/usr/tests/lib/libc/net/getaddrinfo"
_FIXTURES = ['basics_v4.exp', 'basics_v4_only.exp', 'basics_v4v6.exp', 'basics_v4v6_prefer_v4.exp', 'no_host_v4.exp', 'no_host_v4_only.exp', 'no_host_v4v6.exp', 'no_host_v4v6_prefer_v4.exp', 'no_serv_v4.exp', 'no_serv_v4_only.exp', 'no_serv_v4v6.exp', 'no_serv_v4v6_prefer_v4.exp', 'scoped.exp', 'scoped_v4_only.exp', 'scoped_v4v6_prefer_v4.exp', 'sock_raw_v4.exp', 'sock_raw_v4_only.exp', 'sock_raw_v4v6.exp', 'sock_raw_v4v6_prefer_v4.exp', 'spec_fam_v4.exp', 'spec_fam_v4_only.exp', 'spec_fam_v4v6.exp', 'spec_fam_v4v6_prefer_v4.exp', 'unsup_fam.exp', 'unsup_fam_v4_only.exp', 'unsup_fam_v4v6_prefer_v4.exp']

def getaddrinfo_tests():
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared", deps = ["//contrib/atf:c_headers"])
    manifests = []
    for program, source in [("getaddrinfo", "getaddrinfo.c"), ("h_gai", "//contrib/netbsd-tests/lib/libc/net/getaddrinfo:h_gai.c")]:
        bsd_link_sequence(name = program + "_link", deps = ([":atf_interface"] if program == "getaddrinfo" else []) + ["//lib/libc:shared_abi_interface"])
        cc_binary(name = program, srcs = [source], deps = [":" + program + "_link"],
            copts = libc_test_copts(2), defines = ["PIC"], linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None, package = "tests", bindir = _DIRECTORY)
        manifests.append(":" + program + "_install")
    bsd_script_wrapper(name = "getaddrinfo_test", body = "getaddrinfo_test.sh", interpreter = "/usr/libexec/atf-sh",
        cat = "@bsd_sdk//toolchain:cat", cat_runtime = ["@bsd_sdk//toolchain:cat_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")
    bsd_install_file(name = "shell_entry", src = ":getaddrinfo_test", destination = _DIRECTORY + "/getaddrinfo_test",
        owner = "root", group = "wheel", mode = "0555", install_tags = ["package=tests"])
    entries = [":shell_entry"]
    for index, fixture in enumerate(_FIXTURES):
        name = "fixture_" + str(index)
        bsd_install_file(name = name, src = "data/" + fixture, destination = _DIRECTORY + "/data/" + fixture,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
        entries.append(":" + name)
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = ["getaddrinfo", "getaddrinfo_test"], interfaces = {p: "atf" for p in ["getaddrinfo", "getaddrinfo_test"]})
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = entries + [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True, data_subdirectories = ["data"])
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], visibility = ["//visibility:public"], target_compatible_with = _PLATFORM)
