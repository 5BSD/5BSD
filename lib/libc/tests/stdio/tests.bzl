# SPDX-License-Identifier: BSD-2-Clause
"""Original stdio test programs, format policies and declared locale fixtures."""
load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")
load("//share/numericdef:locales.bzl", NUMERIC = "LOCALES", NUMERIC_ALIASES = "ALIASES")
load("//share/numericdef_unicode:locales.bzl", UNICODE_NUMERIC = "LOCALES", UNICODE_ALIASES = "ALIASES")

_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_LOCAL = ["eintr", "fdopen", "flushlbuf", "fmemopen2", "fopen2", "freopen", "getdelim", "gets_s",
    "mkostemp", "open_memstream2", "open_wmemstream", "perror", "print_positional", "printbasic",
    "printfloat", "scanfloat", "snprintf", "sscanf", "swprintf", "swscanf"]
_NETBSD = ["clearerr", "fflush", "fmemopen", "fopen", "fputc", "mktemp", "open_memstream", "popen", "printf", "scanf"]
_ALIASES = {"fopen2": "fopen"}
_NO_FORMAT = ["snprintf", "sscanf", "swprintf", "swscanf"]
_LINK_DEPS = {"eintr": ["//lib/libmd:md_link"], "printfloat": ["//lib/msun:m"], "scanfloat": ["//lib/msun:m"]}
_SHARED = {"eintr": ["//lib/libmd:md_shared"], "printfloat": ["//lib/msun:m_shared"], "scanfloat": ["//lib/msun:m_shared"]}
_CASES = {
    "fmemopen2": ["test_autoalloc", "test_preexisting", "test_data_length", "test_binary", "test_append_binary_pos", "test_size_0", "test_rdonly_wronly"],
    "getdelim": ["getline_basic", "stream_error", "eof", "invalid_params", "nul", "empty_NULL_buffer", "nonblock_eagain_unbuffered", "nonblock_eagain_buffered"],
    "open_memstream2": ["open_group_test", "simple_tests", "seek_tests", "resize_test"],
    "mkostemp": ["zero", "O_CLOEXEC", "O_APPEND", "O_APPEND__O_CLOEXEC", "bad_flags"],
    "printbasic": ["int_within_limits", "int_limits"],
    "printfloat": ["float_within_limits", "infinities_and_nans", "padding", "precision_specifiers", "thousands_separator_and_other_locale_tests", "signed_conversions", "alternate_form", "padding_and_decimal_point_placement", "decimal_rounding", "hexadecimal_floating_point", "hexadecimal_rounding", "subnormal_double", "subnormal_float", "hexadecimal_rounding_fullprec"],
    "scanfloat": ["normalized_numbers", "infinities_and_nans", "rounding_tests", "strtod"],
    "eintr": ["eintr_test"],
} | {stem: [stem + "_" + suffix for suffix in ["b", "B", "d", "x", "X", "wN", "wfN"]] for stem in ["snprintf", "swprintf"]} | {
    stem: [stem + "_" + suffix for suffix in ["b", "o", "d", "x", "i", "wN", "wfN", "termination"]] for stem in ["sscanf", "swscanf"]
}
_LOCALES = {"printfloat": ["hi_IN.ISCII-DEV", "ru_RU.ISO8859-5", "el_GR.ISO8859-7"], "scanfloat": ["ru_RU.ISO8859-5"]} | {
    name: ["en_US.UTF-8"] for name in _NO_FORMAT
}

def _numeric_label(locale):
    # Follow maintained source inventories/aliases rather than duplicating their
    # canonical mapping or resolving against the build host's installed locales.
    for root, locales, aliases in [("numericdef", NUMERIC, NUMERIC_ALIASES), ("numericdef_unicode", UNICODE_NUMERIC, UNICODE_ALIASES)]:
        if locale in locales:
            return "//share/" + root + ":" + locale
        mapping = {alias: source for source, alias in aliases}
        if locale in mapping:
            if mapping[locale] not in locales:
                fail("numeric alias does not name a canonical source locale")
            return "//share/" + root + ":" + mapping[locale]
    fail("missing declared numeric locale: " + locale)

def stdio_tests():
    for policy in [_ALIASES, _NO_FORMAT, _LINK_DEPS, _SHARED, _CASES, _LOCALES]:
        if any([name not in _LOCAL + _NETBSD for name in policy]):
            fail("stdio test policy names an absent program")
    if sorted(_LINK_DEPS.keys()) != sorted(_SHARED.keys()):
        fail("stdio link and runtime library inventories differ")
    locales = sorted({locale: True for names in _LOCALES.values() for locale in names}.keys())
    for locale in locales:
        native.alias(name = "numeric_" + locale, actual = _numeric_label(locale))
    native.filegroup(name = "numeric_fixtures", srcs = [":numeric_" + locale for locale in locales], visibility = ["//visibility:public"])
    manifests = []
    runtime_tests = []
    for name in _LOCAL + _NETBSD:
        program = name + "_test"
        imported = name in _NETBSD
        source = "//contrib/netbsd-tests/lib/libc/stdio:t_" + name + ".c" if imported else _ALIASES.get(name, name) + "_test.c"
        deps = ["//lib/atf/libatf-c:atf_c"] + (["//lib/libnetbsd:netbsd_pie", "//contrib/netbsd-tests:test_headers"] if imported else [])
        cc_binary(name = program, srcs = [source], deps = deps + _LINK_DEPS.get(name, []) + ["//lib/libc:shared_abi_interface"],
            dynamic_deps = ["//lib/atf/libatf-c:atf_c_shared"] + _SHARED.get(name, []),
            defines = ["PIC"], copts = libc_test_copts() + (["-Wno-format"] if name in _NO_FORMAT else []),
            linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None,
            package = "tests", bindir = "/usr/tests/lib/libc/stdio")
        manifests.append(":" + program + "_install")
        for case in _CASES.get(name, []):
            target = program + "_" + case + "_runtime"
            bsd_atf_test(name = target, body = ":" + program, case_name = case, interface = "program",
                runtime_lib = LIBC_TEST_RUNTIME + _SHARED.get(name, []),
                locale_files = {":numeric_" + locale: locale + "/LC_NUMERIC" for locale in _LOCALES.get(name, [])},
                runner = "//tools/build/bazel:atf_runner", test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"},
                size = "small", target_compatible_with = _PLATFORM)
            runtime_tests.append(":" + target)
    programs = sorted([name + "_test" for name in _LOCAL + _NETBSD])
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = programs, interfaces = {p: "atf" for p in programs})
    bsd_install_file(name = "kyuafile_install", src = ":kyuafile", destination = "/usr/tests/lib/libc/stdio/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = [":kyuafile_install"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = "/usr/tests/lib/libc/stdio", manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    native.test_suite(name = "runtime_tests", tests = runtime_tests)
