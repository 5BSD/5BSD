# SPDX-License-Identifier: BSD-2-Clause
"""Original Clang SSP helper programs and shell cases, with native UBSan input."""
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
_CLANG = "//tools/build/bazel/config:clang_enabled"
_SOURCE = "//contrib/netbsd-tests/lib/libc/ssp:"
_DIRECTORY = "/usr/tests/lib/libc/ssp"
_HELPERS = ['h_fgets', 'h_getcwd', 'h_gets', 'h_memcpy', 'h_memmove', 'h_memset', 'h_raw', 'h_read', 'h_readlink', 'h_snprintf', 'h_sprintf', 'h_stpcpy', 'h_stpncpy', 'h_strcat', 'h_strcpy', 'h_strncat', 'h_strncpy', 'h_vsnprintf', 'h_vsprintf']

def ssp_tests():
    cc_import(name = "sys_interface", shared_library = "//lib/libsys:sys_shared")
    cc_import(name = "ubsan_interface", static_library = "//lib/libclang_rt/ubsan_standalone:static_archive", alwayslink = True)
    for name, library in [("thr", "//lib/libthr:thr_shared"), ("rt", "//lib/librt:rt_shared"),
                          ("m", "//lib/msun:m_shared"), ("execinfo", "//lib/libexecinfo:execinfo_shared"), ("gcc_s", "//lib/libgcc_s:gcc_s_shared")]:
        cc_import(name = name + "_interface", shared_library = library)
    manifests = []
    tests = []
    for helper in _HELPERS:
        raw = helper == "h_raw"
        compatible = _PLATFORM + (select({_CLANG: [], "//conditions:default": ["@platforms//:incompatible"]}) if raw else [])
        # Make's h_raw is enabled when its Clang runtime is available. Bazel
        # declares and builds that runtime rather than probing the host sysroot.
        libraries = ([":ubsan_interface"] if raw else []) + [":sys_interface"]
        libraries += ([":" + n + "_interface" for n in ["thr", "rt", "m", "execinfo", "gcc_s"]] if raw else [])
        libraries += ["//lib/libc:shared_abi_interface"]
        bsd_link_sequence(name = helper + "_link", deps = libraries, target_compatible_with = compatible)
        cc_binary(name = helper, srcs = [_SOURCE + helper + ".c"], deps = [":" + helper + "_link"],
            copts = [f for f in libc_test_copts() if f != "-Werror"] + (["-fstack-protector-all", "-Wstack-protector", "-fsanitize=bounds"] if raw else []),
            defines = ["PIC"],
            linkopts = ["-pie", "-nodefaultlibs"] + (["-Wl,--export-dynamic", "-Wl,--enable-new-dtags", "-Wl,-rpath,/usr/lib/clang/21/lib/freebsd"] if raw else []),
            target_compatible_with = compatible)
        utility_installation(name = helper + "_install", program = helper, manual = None, package = "tests", bindir = _DIRECTORY)
        if not raw:
            manifests.append(":" + helper + "_install")
        case = helper.removeprefix("h_")
        test = case + "_runtime"
        bsd_atf_test(name = test, body = _SOURCE + "t_ssp.sh", case_name = case,
            subr = "//libexec/atf/atf-sh:shell_library", data_paths = {":" + helper: helper},
            runtime_bin = ["//bin/sh:sh", "//libexec/atf/atf-sh:atf-sh", "//libexec/atf/atf-check:atf-check", "//usr.bin/dirname:dirname"] + (["//usr.bin/getconf:getconf"] if case == "read" else []),
            runtime_lib = LIBC_TEST_RUNTIME + ["//lib/atf/libatf-c++:atf_cxx_shared", "//lib/libc++:cxx_shared", "//lib/libcxxrt:cxxrt_shared", "//lib/msun:m_shared", "//lib/libgcc_s:gcc_s_shared"] + (["//lib/libthr:thr_shared", "//lib/librt:rt_shared", "//lib/libexecinfo:execinfo_shared", "//lib/libelf:elf_shared"] if raw else []),
            test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, runner = "//tools/build/bazel:atf_runner",
            target_compatible_with = compatible, size = "small")
        tests.append(":" + test)
    bsd_script_wrapper(name = "ssp_test", body = _SOURCE + "t_ssp.sh", interpreter = "/usr/libexec/atf-sh",
        cat = "@bsd_sdk//toolchain:cat", cat_runtime = ["@bsd_sdk//toolchain:cat_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")
    bsd_install_file(name = "shell_entry", src = ":ssp_test", destination = _DIRECTORY + "/ssp_test",
        owner = "root", group = "wheel", mode = "0555", install_tags = ["package=tests"])
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = ["ssp_test"], interfaces = {"ssp_test": "atf"})
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests + select({_CLANG: [":h_raw_install"], "//conditions:default": []}),
        entries = [":shell_entry", ":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    native.test_suite(name = "runtime_tests", tests = tests)
