# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned local libc ATF C programs, fixture files and installation."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load(":test_policy.bzl", "libc_test_copts")
load(":test_runtime.bzl", "LIBC_TEST_RUNTIME")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]

def local_test_installation(programs, directory, warnings, headers = {}, libraries = {}, runtime_libraries = {}, defines = {}, cases = {}, fixtures = {}, metadata = {}, runtime_tags = {}, required_users = {}, stdin_tty_cases = {}):
    """Leaves own sources/options/cases; runtime cases do not limit installation.

    libraries contains ordered native ABI imports or explicit archives. No SDK
    fallback and no library producers are copied into a final consumer.
    """
    if not programs:
        fail("nonempty original program inventory required")
    for mapping in [headers, libraries, runtime_libraries, defines, cases, metadata, runtime_tags, required_users, stdin_tty_cases]:
        if any([p not in programs for p in mapping]):
            fail("per-program policy names an absent program")
    for program, users in required_users.items():
        if any([case not in cases.get(program, []) for case in users]):
            fail("user requirement names an absent selected case")
    for program, tty_cases in stdin_tty_cases.items():
        if any([case not in cases.get(program, []) for case in tty_cases]):
            fail("stdin terminal policy names an absent selected case")
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared", deps = ["//contrib/atf:c_headers"])
    manifests = []
    tests = []
    privileged_tests = []
    for program, source in programs.items():
        bsd_link_sequence(name = program + "_link", deps = [":atf_interface"] + headers.get(program, []) + libraries.get(program, []) + ["//lib/libc:shared_abi_interface"])
        cc_binary(name = program, srcs = [source], deps = [":" + program + "_link"],
            copts = libc_test_copts(warnings), defines = ["PIC"] + defines.get(program, []),
            linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None, package = "tests", bindir = directory)
        manifests.append(":" + program + "_install")
        for case in cases.get(program, []):
            name = program + "_" + case + "_runtime"
            user = required_users.get(program, {}).get(case, "")
            bsd_atf_test(name = name, body = ":" + program, case_name = case, interface = "program",
                runtime_lib = LIBC_TEST_RUNTIME + runtime_libraries.get(program, []), data_paths = fixtures,
                test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, runner = "//tools/build/bazel:atf_runner",
                target_compatible_with = _PLATFORM, size = "small", required_user = user,
                stdin_tty = case in stdin_tty_cases.get(program, []),
                tags = runtime_tags.get(program, []) + (["manual", "external", "no-remote"] if user == "root" else []))
            if user == "root":
                privileged_tests.append(":" + name)
            else:
                tests.append(":" + name)
    entries = []
    for index, (source, dest) in enumerate(fixtures.items()):
        name = "fixture_" + str(index)
        bsd_install_file(name = name, src = source, destination = directory + "/" + dest,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
        entries.append(":" + name)
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = sorted(programs),
        interfaces = {p: "atf" for p in programs}, metadata = {p: json.encode(v) for p, v in metadata.items()})
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = directory + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = entries + [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = directory, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], visibility = ["//visibility:public"], target_compatible_with = _PLATFORM)
    if tests:
        native.test_suite(name = "runtime_tests", tests = tests)
    if privileged_tests:
        native.test_suite(name = "privileged_runtime_tests", tests = privileged_tests, tags = ["manual"])
