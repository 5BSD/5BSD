# SPDX-License-Identifier: BSD-2-Clause
"""Original libc regex programs, shell suites and maintained fixture inventory."""
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
_DIRECTORY = "/usr/tests/lib/libc/regex"
_SOURCE = "//contrib/netbsd-tests/lib/libc/regex:"
_INPUTS = ["anchor", "backref", "basic", "bracket", "c_comments", "complex", "error", "meta", "nospec", "paren", "regress", "repet_bounded", "repet_multi", "repet_ordinary", "startend", "subexp", "subtle", "word_bound", "zero"]
_ATT = ["basic", "categorization", "forcedassoc", "leftassoc", "nullsubexpr", "repetition", "rightassoc"]

def regex_tests():
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared", deps = ["//contrib/atf:c_headers"])
    cc_import(name = "util_interface", shared_library = "//lib/libutil:util_shared", deps = ["//lib/libutil:headers"])
    manifests = []
    runtime_tests = []
    for program, sources in {"h_regex": ["main.c", "split.c", "debug.c"], "exhaust_test": ["t_exhaust.c"], "regex_att_test": ["t_regex_att.c"]}.items():
        atf = program != "h_regex"
        deps = (["//contrib/netbsd-tests/lib/libc/regex:test_headers", "//lib/libc/regex:test_headers"] if not atf else
            [":atf_interface", "//lib/libnetbsd:netbsd_pie", "//contrib/netbsd-tests:test_headers"])
        deps += ([":util_interface"] if program == "regex_att_test" else []) + ["//lib/libc:shared_abi_interface"]
        bsd_link_sequence(name = program + "_link", deps = deps)
        cc_binary(name = program, srcs = [_SOURCE + f for f in sources], deps = [":" + program + "_link"],
            copts = libc_test_copts(3), defines = ["PIC"] + (["REGEX_SPENCER", "SKIP_LEFTASSOC"] if atf else []),
            linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None, package = "tests", bindir = _DIRECTORY)
        manifests.append(":" + program + "_install")
    bsd_atf_test(name = "exhaust_runtime", body = ":exhaust_test", case_name = "regcomp_too_big", interface = "program",
        runtime_lib = LIBC_TEST_RUNTIME, test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"},
        body_timeout_seconds = 600, runner = "//tools/build/bazel:atf_runner", size = "large", target_compatible_with = _PLATFORM)
    runtime_tests.append(":exhaust_runtime")
    for case in _ATT:
        name = "att_" + case + "_runtime"
        bsd_atf_test(name = name, body = ":regex_att_test", case_name = case, interface = "program",
            data_paths = {_SOURCE + "data/att/" + n + ".dat": "data/" + n + ".dat" for n in _ATT},
            runtime_lib = LIBC_TEST_RUNTIME + ["//lib/libutil:util_shared"],
            test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, runner = "//tools/build/bazel:atf_runner",
            target_compatible_with = _PLATFORM, size = "small")
        runtime_tests.append(":" + name)
    shell_runtime = LIBC_TEST_RUNTIME + ["//lib/atf/libatf-c++:atf_cxx_shared", "//lib/libc++:cxx_shared", "//lib/libcxxrt:cxxrt_shared", "//lib/msun:m_shared", "//lib/libgcc_s:gcc_s_shared"]
    for suite, body, cases in [("regex_test", _SOURCE + "t_regex.sh", _INPUTS), ("multibyte", "multibyte.sh", ["bmpat", "icase", "mbset"])]:
        for case in cases:
            name = suite + "_" + case + "_runtime"
            bsd_atf_test(name = name, body = body, case_name = case,
                subr = "//libexec/atf/atf-sh:shell_library",
                data_paths = {_SOURCE + "data/" + n + ".in": "data/" + n + ".in" for n in _INPUTS} | {":h_regex": "h_regex"},
                runtime_bin = ["//bin/sh:sh", "//libexec/atf/atf-sh:atf-sh", "//libexec/atf/atf-check:atf-check", "//usr.bin/sed:sed", "//bin/rm:rm", "//usr.bin/dirname:dirname"],
                runtime_lib = shell_runtime, locale_files = {"//share/ctypedef:C.UTF-8": "C.UTF-8/LC_CTYPE"},
                cleanup = suite == "multibyte" and case == "mbset",
                test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, runner = "//tools/build/bazel:atf_runner",
                target_compatible_with = _PLATFORM, size = "small")
            runtime_tests.append(":" + name)
    entries = []
    for program, body in [("multibyte", "multibyte.sh"), ("regex_test", _SOURCE + "t_regex.sh")]:
        bsd_script_wrapper(name = program, body = body, interpreter = "/usr/libexec/atf-sh",
            cat = "@bsd_sdk//toolchain:cat", cat_runtime = ["@bsd_sdk//toolchain:cat_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")
        name = program + "_entry"
        bsd_install_file(name = name, src = ":" + program, destination = _DIRECTORY + "/" + program,
            owner = "root", group = "wheel", mode = "0555", install_tags = ["package=tests"])
        entries.append(":" + name)
    files = [(_SOURCE + "README", "README")]
    files += [(_SOURCE + "data/" + n + ".in", "data/" + n + ".in") for n in _INPUTS]
    files += [(_SOURCE + "data/att/" + n + ".dat", "data/" + n + ".dat") for n in _ATT]
    for index, (source, dest) in enumerate(files):
        name = "fixture_" + str(index)
        bsd_install_file(name = name, src = source, destination = _DIRECTORY + "/" + dest,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
        entries.append(":" + name)
    programs = ["exhaust_test", "multibyte", "regex_att_test", "regex_test"]
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = programs, interfaces = {p: "atf" for p in programs})
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = entries + [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], visibility = ["//visibility:public"], target_compatible_with = _PLATFORM)
    native.test_suite(name = "runtime_tests", tests = runtime_tests)
