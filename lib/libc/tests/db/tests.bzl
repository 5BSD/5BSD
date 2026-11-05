# SPDX-License-Identifier: BSD-2-Clause
"""Original DB tests, helper programs, transformed shell suite and data."""
load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_script_wrapper")
load("//tools/build/bazel:bsd_sed_output.bzl", "bsd_sed_output")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")

_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_DIRECTORY = "/usr/tests/lib/libc/db"
_CASES = {
    "dbm_open_test": ["dbm_open_missing_test", "dbm_open_wronly_test"],
    "dbm_perm_test": ["dbm_rdonly_test", "dbm_wronly_test", "dbm_rdwr_test"],
    "dbm_nextkey_test": ["dbm_nextkey_test", "dbm_nextkey_cursor_test"],
    "db_hash_tamper_test": ["db_hash_ovflw_point_test", "db_hash_bpages_test", "db_hash_bsize_test", "db_hash_masks_test", "db_hash_call_hash_oob_test"],
    "db_hash_seq_test": ["test_hash_del_none", "test_hash_del_all", "test_hash_del_alt", "test_hash_del_every_7"],
}

def db_tests():
    manifests = []
    runtime_tests = []
    for program in list(_CASES.keys()) + ["h_db", "h_lfsr"]:
        imported = program in ["h_db", "h_lfsr", "db_hash_seq_test"]
        source = ("//contrib/netbsd-tests/lib/libc/db:" +
            ("t_db_hash_seq.c" if program == "db_hash_seq_test" else program + ".c")) if imported else program + ".c"
        atf = program in _CASES
        # Original NetBSD compatibility linkage belongs only to db_hash_seq_test.
        deps = (["//lib/libc/db:test_headers"] + (["//lib/atf/libatf-c:atf_c"] if atf else []) +
            (["//lib/libnetbsd:netbsd_pie", "//contrib/netbsd-tests:test_headers"] if program == "db_hash_seq_test" else []) +
            ["//lib/libc:shared_abi_interface"])
        cc_binary(name = program, srcs = [source], deps = deps,
            dynamic_deps = ["//lib/atf/libatf-c:atf_c_shared"] if atf else [],
            defines = ["PIC"], copts = libc_test_copts(), linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None,
            package = "tests", bindir = _DIRECTORY)
        manifests.append(":" + program + "_install")
        for case in _CASES.get(program, []):
            target = program + "_" + case + "_runtime"
            bsd_atf_test(name = target, body = ":" + program, case_name = case, interface = "program",
                runtime_lib = LIBC_TEST_RUNTIME, runner = "//tools/build/bazel:atf_runner",
                test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, size = "small", target_compatible_with = _PLATFORM)
            runtime_tests.append(":" + target)
    bsd_sed_output(name = "db_body", template = "//contrib/netbsd-tests/lib/libc/db:t_db.sh", output = "db_test.body",
        arguments = ["-e", "s,/bin/csh,/bin/cat,g"], sed = "@bsd_sdk//toolchain:sed",
        runtime = ["@bsd_sdk//toolchain:sed_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")
    bsd_script_wrapper(name = "db_test", body = ":db_body", interpreter = "/usr/libexec/atf-sh",
        cat = "@bsd_sdk//toolchain:cat", cat_runtime = ["@bsd_sdk//toolchain:cat_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")
    bsd_install_file(name = "shell_install", src = ":db_test", destination = _DIRECTORY + "/db_test",
        owner = "root", group = "wheel", mode = "0555", install_tags = ["package=tests"])
    bsd_install_file(name = "readme_install", src = "//contrib/netbsd-tests/lib/libc/db:README", destination = _DIRECTORY + "/README",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    programs = list(_CASES.keys()) + ["db_test"]
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = sorted(programs), interfaces = {p: "atf" for p in programs})
    bsd_install_file(name = "kyuafile_install", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = [":shell_install", ":readme_install", ":kyuafile_install"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    native.test_suite(name = "runtime_tests", tests = runtime_tests)
