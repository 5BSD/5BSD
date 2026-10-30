# SPDX-License-Identifier: BSD-2-Clause
"""Native ATF targets derived from the explicit maintained shell fixture lists."""
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")

def shell_tests(fixtures):
    cases = []
    for fixture in fixtures:
        parts = fixture.rsplit(".", 1)
        if len(parts) != 2 or not parts[1] or any([c not in "0123456789" for c in parts[1].elems()]):
            continue
        case = parts[0].replace("-", "_") + "_exit_" + parts[1]
        if case in cases:
            fail("shell fixture case identity collision: " + case)
        cases.append(case)
    if not cases:
        fail("shell test group must declare at least one case")
    for case in cases:
        bsd_atf_test(
            name = "native_" + case,
            case_name = case,
            body = "//bin/sh/tests:functional_test.sh",
            subr = "//libexec/atf/atf-sh:shell_library",
            data = fixtures,
            config_files = {"//bin/sh:sh": "bin.sh.test_shell"},
            runtime_bin = ["//bin/sh:sh", "//libexec/atf/atf-sh:atf-sh", "//libexec/atf/atf-check:atf-check", "//usr.bin/find:find", "//usr.bin/dirname:dirname", "//usr.bin/tr:tr", "//bin/rm:rm", "//bin/rmdir:rmdir", "//bin/date:date", "//bin/dd:dd", "//usr.bin/id:id", "//bin/ln:ln", "//usr.bin/touch:touch", "//usr.bin/mktemp:mktemp", "//usr.bin/printf:printf", "//usr.bin/script:script", "//usr.bin/ktrace:ktrace", "//bin/kill:kill", "//bin/ps:ps", "//bin/ls:ls", "//bin/cat:cat", "//bin/mkdir:mkdir", "//bin/chmod:chmod", "//usr.bin/mkfifo:mkfifo", "//bin/sleep:sleep", "//bin/echo:echo", "//bin/pwd:pwd", "//bin/test:test", "//bin/expr:expr", "//usr.bin/env:env", "//usr.bin/grep:grep", "//usr.bin/sed:sed", "//usr.bin/head:head", "//usr.bin/tail:tail", "//usr.bin/wc:wc", "//usr.bin/sort:sort", "//usr.bin/basename:basename", "//usr.bin/cut:cut", "//usr.bin/true:true", "//usr.bin/false:false", "//usr.bin/diff:diff", "//usr.bin/cmp:cmp", "//usr.bin/jot:jot", "//usr.bin/seq:seq"],
            runtime_lib = ["//lib/atf/libatf-c:atf_c_shared", "//lib/atf/libatf-c++:atf_cxx_shared", "//lib/libc++:cxx_shared", "//lib/libcxxrt:cxxrt_shared", "//lib/msun:m_shared", "//lib/libedit:edit_shared", "//lib/ncurses/tinfo:tinfo_shared", "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7", "@bsd_sdk//toolchain:sysroot/lib/libgcc_s.so.1", "//lib/libutil:util_shared", "//lib/libkvm:kvm_shared", "//lib/libelf:elf_shared", "//lib/libjail:jail_shared", "//lib/libregex:regex_shared", "//lib/libmd:md_shared", "//lib/libxo/libxo:xo_shared", "//lib/libnv:nv_shared", "//lib/libcasper/libcasper:casper_shared", "//lib/libcasper/services/cap_fileargs:cap_fileargs_shared"],
            runner = "//tools/build/bazel:atf_runner",
            size = "small",
        )
    native.test_suite(name = "tests", tests = [":native_" + case for case in cases], visibility = ["//visibility:public"])
