# SPDX-License-Identifier: BSD-2-Clause
"""Original local/NetBSD locale programs with source-owned aliases and data."""
load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")
load("//share/ctypedef:installation.bzl", CTYPE = "LOCALES", CTYPE_ALIASES = "ALIASES")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_LOCAL = ["btowc", "c16rtomb", "iswctype", "mblen", "mbrlen", "mbrtoc16", "mbrtowc_2", "mbsnrtowcs_2", "mbsrtowcs", "mbstowcs_2", "mbtowc_2", "newlocale", "towctrans", "wcrtomb", "wcsnrtombs", "wcsrtombs", "wcstombs", "wctomb_2"]
_NETBSD = ["iconv", "mbrtowc", "mbstowcs", "mbsnrtowcs", "mbtowc", "wcscspn", "wcspbrk", "wcsspn", "wcstod", "wctomb"]
_ALIASES = {"mbrtowc_2": "mbrtowc", "mbsnrtowcs_2": "mbsnrtowcs", "mbstowcs_2": "mbstowcs", "mbtowc_2": "mbtowc", "wctomb_2": "wctomb"}
_CASES = {
    "btowc": ["btowc_test"],
    "c16rtomb": ["c16rtomb_c_locale_test", "c16rtomb_iso_8859_1_test", "c16rtomb_iso_8859_15_test", "c16rtomb_utf_8_test"],
    "iswctype": ["iswctype_c_locale_test", "iswctype_euc_jp_test"],
    "mblen": ["mblen_test"],
    "mbrlen": ["mbrlen_test"],
    "mbrtoc16": ["mbrtoc16_c_locale_test", "mbrtoc16_iso_8859_1_test", "mbrtoc16_iso_8859_15_test", "mbrtoc16_utf_8_test"],
    "mbrtowc_2": ["mbrtowc_test"],
    "mbsnrtowcs_2": ["mbsnrtowcs_test"],
    "mbsrtowcs": ["mbsrtowcs_test"],
    "mbstowcs_2": ["mbstowcs_test"],
    "mbtowc_2": ["mbtowc_test"],
    "newlocale": ["newlocale_c_posix_cu8_test"],
    "towctrans": ["towctrans_test"],
    "wcrtomb": ["wcrtomb_test"],
    "wcsnrtombs": ["wcsnrtombs_test"],
    "wcsrtombs": ["wcsrtombs_test"],
    "wcstombs": ["wcstombs_test"],
    "wctomb_2": ["euccs1_test", "wctomb_test"],
    "iconv": ["iconv_pr59019_hz8", "iconv_samples"],
    "mbrtowc": ["mbrtowc_internal", "mbrtowc_object"],
    "mbstowcs": ["mbstowcs_basic"],
    "mbsnrtowcs": ["mbsnrtowcs"],
    "mbtowc": ["mbtowc"],
    "wcscspn": ["wcscspn"],
    "wcspbrk": ["wcspbrk"],
    "wcsspn": ["wcsspn"],
    "wcstod": ["wcstod"],
    "wctomb": ["wctomb", "wcrtomb", "wcrtomb_state"],
}
_LOCALES = {
    "btowc": ["ja_JP.eucJP"],
    "c16rtomb": ["en_US.ISO8859-1", "en_US.ISO8859-15", "en_US.UTF-8"],
    "iswctype": ["ja_JP.eucJP"],
    "mblen": ["ja_JP.eucJP"],
    "mbrlen": ["ja_JP.eucJP"],
    "mbrtoc16": ["en_US.ISO8859-1", "en_US.ISO8859-15", "en_US.UTF-8"],
    "mbrtowc_2": ["ja_JP.eucJP"],
    "mbsnrtowcs_2": ["ja_JP.eucJP"],
    "mbsrtowcs": ["ja_JP.eucJP"],
    "mbstowcs_2": ["ja_JP.eucJP"],
    "mbtowc_2": ["ja_JP.eucJP"],
    "newlocale": ["C.UTF-8"],
    "towctrans": ["ja_JP.eucJP"],
    "wcrtomb": ["ja_JP.eucJP"],
    "wcsnrtombs": ["ja_JP.eucJP"],
    "wcsrtombs": ["ja_JP.eucJP"],
    "wcstombs": ["ja_JP.eucJP"],
    "wctomb_2": ["ja_JP.eucJP", "zh_CN.eucCN"],
    "mbrtowc": ["en_US.UTF-8", "ja_JP.SJIS", "ja_JP.eucJP"],
    "mbstowcs": ["en_US.UTF-8", "ja_JP.SJIS", "ja_JP.eucJP"],
    "mbsnrtowcs": ["en_US.UTF-8"],
    "mbtowc": ["en_US.UTF-8", "ja_JP.SJIS", "ja_JP.eucJP", "zh_CN.GB18030", "zh_TW.Big5"],
}
# These programs need real absolute-path Citrus modules/data. Their original
# cases remain installed, to run in the installed-resource VM qualification.
_INSTALLED_RESOURCE_PROGRAMS = ["c16rtomb", "mbrtoc16", "iconv"]

def _ctype_label(locale):
    if locale in CTYPE:
        return "//share/ctypedef:" + locale
    mapping = {alias: source for source, alias in CTYPE_ALIASES}
    if locale not in mapping or mapping[locale] not in CTYPE:
        fail("locale test requires missing maintained ctype data: " + locale)
    return "//share/ctypedef:" + mapping[locale]

def locale_tests():
    for mapping in [_ALIASES, _CASES, _LOCALES]:
        if any([p not in _LOCAL + _NETBSD for p in mapping]):
            fail("locale policy names an absent program")
    fixtures = sorted({locale: True for values in _LOCALES.values() for locale in values})
    for locale in fixtures:
        native.alias(name = "ctype_" + locale, actual = _ctype_label(locale))
    native.filegroup(name = "ctype_fixtures", srcs = [":ctype_" + locale for locale in fixtures], visibility = ["//visibility:public"])
    manifests = []
    tests = []
    for name in _LOCAL + _NETBSD:
        imported = name in _NETBSD
        program = name + "_test"
        source = "//contrib/netbsd-tests/lib/libc/locale:t_" + name + ".c" if imported else _ALIASES.get(name, name) + "_test.c"
        deps = ["//lib/atf/libatf-c:atf_c"] + (["//lib/libnetbsd:netbsd_pie", "//contrib/netbsd-tests:test_headers"] if imported else [])
        cc_binary(name = program, srcs = [source], deps = deps + ["//lib/libc:shared_abi_interface"],
            dynamic_deps = ["//lib/atf/libatf-c:atf_c_shared"], copts = libc_test_copts() + (["-Wno-stack-protector"] if imported and name == "wctomb" else []),
            defines = ["PIC"], linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None, package = "tests", bindir = "/usr/tests/lib/libc/locale")
        manifests.append(":" + program + "_install")
        if name in _INSTALLED_RESOURCE_PROGRAMS:
            continue
        for case in _CASES[name]:
            target = program + "_" + case + "_runtime"
            bsd_atf_test(name = target, body = ":" + program, case_name = case, interface = "program",
                runtime_lib = LIBC_TEST_RUNTIME, locale_files = {":ctype_" + locale: locale + "/LC_CTYPE" for locale in _LOCALES.get(name, [])},
                runner = "//tools/build/bazel:atf_runner", test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"},
                size = "small", target_compatible_with = _PLATFORM)
            tests.append(":" + target)
    programs = sorted([name + "_test" for name in _LOCAL + _NETBSD])
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = programs, interfaces = {p: "atf" for p in programs})
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = "/usr/tests/lib/libc/locale/Kyuafile", owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = "/usr/tests/lib/libc/locale", manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], visibility = ["//visibility:public"], target_compatible_with = _PLATFORM)
    native.test_suite(name = "runtime_tests", tests = tests)
