# SPDX-License-Identifier: BSD-2-Clause
"""Complete original string test compilation, textual inputs and installation."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")

_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_LOCAL = ["bcmp", "ffs", "ffsl", "ffsll", "fls", "flsl", "flsll", "memccpy", "memcmp", "memrchr",
    "memset2", "memset_s", "strncmp", "stpncpy", "strnlen", "strcmp2", "strcspn", "strerror2",
    "strlcpy", "strrchr2", "strspn", "strverscmp", "strxfrm", "timingsafe_bcmp", "timingsafe_memcmp",
    "wcscasecmp", "wcscoll", "wcsnlen"]
_NETBSD = ["memchr", "memcpy", "memmem", "memset", "strcat", "strchr", "strchrnul", "strcmp",
    "strcpy", "strerror", "strlen", "strpbrk", "strrchr", "swab"]
_MD = ["memchr", "memcpy"]
_ALIASES = {"memset2": "memset", "strcmp2": "strcmp", "strerror2": "strerror", "strrchr2": "strrchr"}
_TEXTUAL = {"bcmp": "memcmp", "ffsl": "ffs", "ffsll": "ffs", "flsl": "fls", "flsll": "fls",
    "strspn": "strcspn", "timingsafe_bcmp": "memcmp", "timingsafe_memcmp": "memcmp"}
_CASES = {name: ["zero", "twobit", "twobitneg"] for name in ["ffs", "ffsl", "ffsll", "fls", "flsl", "flsll"]} | {
    "strverscmp": ["strcmp_functionality", "vers_ordering", "natural_ordering", "glibc_bug_9913", "semver_ordering"],
    "strnlen": ["strnlen_alignments", "strnlen_size_max"],
    "memchr": ["memchr_basic", "memchr_simple", "memrchr_simple"],
    "memcpy": ["memcpy_basic", "memcpy_return", "memccpy_simple"],
}

def string_tests():
    for policy in [_ALIASES, _TEXTUAL, _CASES, _MD]:
        if any([name not in _LOCAL + _NETBSD for name in policy]):
            fail("string test policy names an absent program")
    for body in sorted({v: True for v in _TEXTUAL.values()}.keys()):
        cc_library(name = "textual_" + body, textual_hdrs = [body + "_test.c"])
    manifests = []
    runtime_tests = []
    for name in _LOCAL + _NETBSD:
        program = name + "_test"
        imported = name in _NETBSD
        source = "//contrib/netbsd-tests/lib/libc/string:t_" + name + ".c" if imported else _ALIASES.get(name, name) + "_test.c"
        deps = ["//lib/atf/libatf-c:atf_c"]
        if imported:
            deps += ["//lib/libnetbsd:netbsd_pie", "//contrib/netbsd-tests:test_headers"]
        if name in _TEXTUAL:
            deps.append(":textual_" + _TEXTUAL[name])
        if name in _MD:
            deps.append("//lib/libmd:md_link")
        deps.append("//lib/libc:shared_abi_interface")
        shared = ["//lib/libmd:md_shared"] if name in _MD else []
        cc_binary(name = program, srcs = [source], deps = deps, defines = ["PIC"],
            dynamic_deps = ["//lib/atf/libatf-c:atf_c_shared"] + shared,
            copts = libc_test_copts() + ["-fno-builtin"], linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None,
            package = "tests", bindir = "/usr/tests/lib/libc/string")
        manifests.append(":" + program + "_install")
        for case in _CASES.get(name, []):
            target = program + "_" + case + "_runtime"
            bsd_atf_test(name = target, body = ":" + program, case_name = case, interface = "program",
                runtime_lib = LIBC_TEST_RUNTIME + shared, runner = "//tools/build/bazel:atf_runner",
                test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, size = "small", target_compatible_with = _PLATFORM)
            runtime_tests.append(":" + target)
    programs = sorted([name + "_test" for name in _LOCAL + _NETBSD])
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = programs, interfaces = {p: "atf" for p in programs})
    bsd_install_file(name = "kyuafile_install", src = ":kyuafile", destination = "/usr/tests/lib/libc/string/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = [":kyuafile_install"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = "/usr/tests/lib/libc/string", manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    native.test_suite(name = "runtime_tests", tests = runtime_tests)
