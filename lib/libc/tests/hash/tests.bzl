# SPDX-License-Identifier: BSD-2-Clause
"""Original hash helper, optional SHA2 program, shell suite and fixtures."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_script_wrapper")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_OPENSSL = "//tools/build/bazel/config:openssl_enabled"
_SOURCE = "//contrib/netbsd-tests/lib/libc/hash:"
_DIRECTORY = "/usr/tests/lib/libc/hash"
_FIXTURES = ["md5test-in", "md5test-out", "sha1test-in", "sha1test-out", "sha1test2-out"]

def hash_tests():
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared", deps = ["//contrib/atf:c_headers"])
    cc_import(name = "md_interface", shared_library = "//lib/libmd:md_shared", deps = ["//lib/libmd:headers"])
    cc_import(name = "crypto_interface", shared_library = "//secure/lib/libcrypto:crypto_shared")
    for program, source in [("h_hash", "h_hash.c"), ("sha2_test", "t_sha2.c")]:
        atf = program == "sha2_test"
        # Original global LIBADD=md precedes per-program crypto. Preserve the
        # actual unreferenced crypto NEEDED entry as well as the symbol providers.
        deps = ([":atf_interface", "//lib/libnetbsd:netbsd_pie", "//contrib/netbsd-tests:test_headers"] if atf else ["//lib/libnetbsd:sha1_header"])
        deps += [":md_interface"] + ([":crypto_interface"] if atf else []) + ["//lib/libc:shared_abi_interface"]
        compatible = _PLATFORM + (select({_OPENSSL: [], "//conditions:default": ["@platforms//:incompatible"]}) if atf else [])
        bsd_link_sequence(name = program + "_link", deps = deps, target_compatible_with = compatible)
        cc_binary(name = program, srcs = [_SOURCE + source], deps = [":" + program + "_link"],
            copts = libc_test_copts(), defines = ["PIC"], linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = compatible)
        utility_installation(name = program + "_install", program = program, manual = None, package = "tests", bindir = _DIRECTORY)
    sha_cases = []
    for case in ["t_sha256", "t_sha384", "t_sha512"]:
        name = case + "_runtime"
        bsd_atf_test(name = name, body = ":sha2_test", case_name = case, interface = "program",
            runtime_lib = LIBC_TEST_RUNTIME + ["//lib/libmd:md_shared", "//secure/lib/libcrypto:crypto_shared", "//lib/libthr:thr_shared"],
            test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, runner = "//tools/build/bazel:atf_runner",
            target_compatible_with = _PLATFORM + select({_OPENSSL: [], "//conditions:default": ["@platforms//:incompatible"]}), size = "small")
        sha_cases.append(":" + name)
    shell_runtime = LIBC_TEST_RUNTIME + ["//lib/libmd:md_shared", "//lib/atf/libatf-c++:atf_cxx_shared", "//lib/libc++:cxx_shared", "//lib/libcxxrt:cxxrt_shared", "//lib/msun:m_shared", "//lib/libgcc_s:gcc_s_shared"]
    shell_cases = []
    for case in ["md5", "sha1"]:
        name = "hash_" + case + "_runtime"
        bsd_atf_test(name = name, body = _SOURCE + "t_hash.sh", case_name = case,
            subr = "//libexec/atf/atf-sh:shell_library",
            data_paths = {_SOURCE + "data/" + n: "data/" + n for n in _FIXTURES} | {":h_hash": "h_hash"},
            runtime_bin = ["//bin/sh:sh", "//libexec/atf/atf-sh:atf-sh", "//libexec/atf/atf-check:atf-check", "//usr.bin/dirname:dirname", "//usr.bin/jot:jot"],
            runtime_lib = shell_runtime, test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"},
            runner = "//tools/build/bazel:atf_runner", target_compatible_with = _PLATFORM, size = "small")
        shell_cases.append(":" + name)
    bsd_script_wrapper(name = "hash_test", body = _SOURCE + "t_hash.sh", interpreter = "/usr/libexec/atf-sh",
        cat = "@bsd_sdk//toolchain:cat", cat_runtime = ["@bsd_sdk//toolchain:cat_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")
    bsd_install_file(name = "shell_entry", src = ":hash_test", destination = _DIRECTORY + "/hash_test",
        owner = "root", group = "wheel", mode = "0555", install_tags = ["package=tests"])
    entries = [":shell_entry"]
    for index, fixture in enumerate(_FIXTURES):
        name = "fixture_" + str(index)
        bsd_install_file(name = name, src = _SOURCE + "data/" + fixture, destination = _DIRECTORY + "/data/" + fixture,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
        entries.append(":" + name)
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = ["hash_test"] + select({_OPENSSL: ["sha2_test"], "//conditions:default": []}),
        interfaces = select({_OPENSSL: {"hash_test": "atf", "sha2_test": "atf"}, "//conditions:default": {"hash_test": "atf"}}))
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = [":h_hash_install"] + select({_OPENSSL: [":sha2_test_install"], "//conditions:default": []}), entries = entries + [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    native.test_suite(name = "runtime_tests", tests = shell_cases + sha_cases)
