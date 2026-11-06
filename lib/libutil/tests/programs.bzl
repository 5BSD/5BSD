# SPDX-License-Identifier: BSD-2-Clause
"""Original libutil test objects and native final link boundaries."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import", "cc_library")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
_PROGRAMS = [('cpuset_test', ['cpuset_test.c'], [], ['-pie'], []), ('expand_number_test', ['expand_number_test.c'], [], ['-pie'], []), ('flopen_test', ['flopen_test.c'], [], ['-pie'], []), ('forkpty_test', ['forkpty_test.c'], [], ['-pie'], []), ('getlocalbase_test', ['getlocalbase_test.c'], [], ['-pie'], []), ('grp_test', ['grp_test.c'], [], ['-pie'], []), ('humanize_number_test', ['humanize_number_test.c'], [], ['-pie'], []), ('login_cap_list_test', ['login_cap_list_test.c', '//lib/libutil:login_cap.c', '//lib/libc/gen:getcap.c'], ['-Ilib/libutil', '-Iinclude', '-Ilib/libc/include'], ['-pie', '-Wl,--wrap=cgetstr', '-Wl,--wrap=free', '-Wl,--wrap=realloc', '-Wl,--wrap=reallocarray'], ['//include:libutil_test_headers', '//lib/libc/include:libutil_test_headers']), ('login_time_error_test', ['login_time_error_test.c', '//lib/libutil:login_ok.c', '//lib/libutil:login_times.c'], [], ['-pie', '-Wl,--wrap=localtime', '-Wl,--wrap=localtime_r'], []), ('pidfile_test', ['pidfile_test.c'], [], ['-pie'], []), ('trimdomain-nodomain_test', ['trimdomain-nodomain_test.c'], [], ['-pie'], []), ('trimdomain_test', ['trimdomain_test.c'], [], ['-pie'], [])]
_ATF = ["cpuset_test", "expand_number_test", "forkpty_test", "getlocalbase_test", "login_time_error_test", "login_cap_list_test"]

def util_test_programs(copts, compat):
    cc_import(name = "test_atf_abi", shared_library = "//lib/atf/libatf-c:atf_c_shared")
    cc_import(name = "test_util_abi", shared_library = "//lib/libutil:util_shared")
    for name, sources, extra_copts, linkopts, extra_headers in _PROGRAMS:
        atf = name in _ATF
        cc_library(name = name + "_objects", srcs = sources, copts = copts + extra_copts,
            deps = ["//lib/libutil:headers"] + (["//contrib/atf:c_headers"] if atf else []) + extra_headers,
            alwayslink = True, target_compatible_with = compat)
        bsd_link_sequence(name = name + "_link", object_groups = [":" + name + "_objects"],
            deps = ([":test_atf_abi"] if atf else []) + [":test_util_abi", "//lib/libc:shared_abi_interface"], target_compatible_with = compat)
        for suffix in ([""] if atf else ["", "_qualification"]):
            cc_binary(name = name + suffix, deps = [":" + name + "_link"],
                linkopts = linkopts + ["-nodefaultlibs"] + (["-Wl,--disable-new-dtags,-rpath,$ORIGIN"] if suffix else []),
                target_compatible_with = compat)
