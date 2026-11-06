# SPDX-License-Identifier: BSD-2-Clause
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")
load("@bazel_skylib//rules:write_file.bzl", "write_file")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_copy_file")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_DIRECTORY = "/usr/tests/lib/libc/gen/posix_spawn"
_SOURCE = "//contrib/netbsd-tests/lib/libc/gen/posix_spawn:"
_CASES = {'fileactions_test': ['t_spawn_fileactions',
                      't_spawn_open_nonexistent',
                      't_spawn_reopen',
                      't_spawn_openmode',
                      't_spawn_empty_fileactions',
                      't_spawn_chdir',
                      't_spawn_fchdir'],
 'spawn_test': ['t_spawn_ls',
                't_spawnp_ls',
                't_spawn_zero',
                't_spawn_missing',
                't_spawn_nonexec',
                't_spawn_child'],
 'spawnattr_test': ['t_spawnattr']}
_CLEANUP = {'fileactions_test': [], 'spawn_test': [], 'spawnattr_test': []}
_USERS = {'fileactions_test': {}, 'spawn_test': {}, 'spawnattr_test': {'t_spawnattr': 'root'}}
_TIMEOUTS = {'fileactions_test': {}, 'spawn_test': {}, 'spawnattr_test': {}}
_HELPERS = ['h_fileactions', 'h_spawn', 'h_spawnattr']

def child_tests():
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared", deps = ["//contrib/atf:c_headers"])
    manifests = []
    deferred = []
    entries = []
    # Exact original /dev/zero fixture: 1 KiB blocks, count 2, no trailing text.
    write_file(name = "zero_fixture", out = "h_zero", content = [json.decode('"\\u0000"') * 2048], is_executable = True)
    bsd_copy_file(name = "nonexec_fixture", src = _SOURCE + "h_nonexec.sh", output = "h_nonexec", make_executable = True,
        cat = "@bsd_sdk//toolchain:cat", runtime = ["@bsd_sdk//toolchain:cat_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")
    for name, source in [("h_zero", ":zero_fixture"), ("h_nonexec", ":nonexec_fixture")]:
        bsd_install_file(name = name + "_entry", src = source, destination = _DIRECTORY + "/" + name,
            owner = "root", group = "wheel", mode = "0555", install_tags = ["package=tests"])
        entries.append(":" + name + "_entry")
    for program in _CASES.keys() + _HELPERS:
        atf = program in _CASES
        deps = ([":atf_interface", "//lib/libnetbsd:netbsd_pie", "//contrib/netbsd-tests:test_headers"] if atf else []) + ["//lib/libc:shared_abi_interface"]
        bsd_link_sequence(name = program + "_link", deps = deps)
        cc_binary(name = program, srcs = [_SOURCE + ("t_" + program[:-5] + ".c" if atf else program + ".c")], deps = [":" + program + "_link"],
            copts = libc_test_copts(), defines = ["PIC"], linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None, package = "tests", bindir = _DIRECTORY)
        manifests.append(":" + program + "_install")
        for case in _CASES.get(program, []):
            name = program + "_" + case + "_runtime"
            timeout = _TIMEOUTS.get(program, {}).get(case, 0)
            bsd_atf_test(name = name, body = ":" + program, case_name = case, interface = "program",
                data_paths = {":" + helper: helper for helper in _HELPERS} | {":zero_fixture": "h_zero", ":nonexec_fixture": "h_nonexec"}, runtime_lib = LIBC_TEST_RUNTIME,
                required_user = _USERS.get(program, {}).get(case, ""), cleanup = case in _CLEANUP.get(program, []), body_timeout_seconds = timeout,
                tags = ["manual", "external", "no-remote"], runner = "//tools/build/bazel:atf_runner", test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"},
                size = "large" if timeout >= 300 else ("medium" if timeout >= 60 else "small"), target_compatible_with = _PLATFORM)
            deferred.append(":" + name)
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = sorted(_CASES.keys()), interfaces = {p: "atf" for p in _CASES})
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = entries + [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], visibility = ["//visibility:public"], target_compatible_with = _PLATFORM)
    native.test_suite(name = "deferred_runtime_tests", tests = deferred, tags = ["manual"])
