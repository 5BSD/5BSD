# SPDX-License-Identifier: BSD-2-Clause
"""Original Casper service tests and native ABI/install boundaries."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import", "cc_library")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_kyuafile")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_kyua.bzl", "bsd_kyua_test")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"] + select({
    "//tools/build/bazel/config:casper_enabled": [], "//conditions:default": ["@platforms//:incompatible"],
})

def casper_service_test(service, program, interface = "atf", warnings = 6, metadata = "{}"):
    directory = "/usr/tests/lib/libcasper/services/" + service
    package = "//lib/libcasper/services/" + service
    cc_import(name = "casper_abi", shared_library = "//lib/libcasper/libcasper:casper_shared")
    cc_import(name = "service_abi", shared_library = package + ":" + service + "_shared")
    cc_import(name = "nv_abi", shared_library = "//lib/libnv:nv_shared")
    if interface == "atf":
        cc_import(name = "atf_abi", shared_library = "//lib/atf/libatf-c:atf_c_shared")
    elif interface != "tap":
        fail("unsupported Casper test interface")
    cc_library(name = program + "_objects", srcs = [program + ".c"],
        deps = ["//lib/libcasper/libcasper:headers", package + ":headers", "//sys/sys:nv_headers"] + (["//contrib/atf:c_headers"] if interface == "atf" else []),
        copts = libc_test_copts(warnings), defines = ["PIC", "WITH_CASPER"], alwayslink = True, target_compatible_with = _PLATFORM)
    bsd_link_sequence(name = program + "_link", object_groups = [":" + program + "_objects"],
        deps = ([":atf_abi"] if interface == "atf" else []) + [":casper_abi", ":service_abi", ":nv_abi", "//lib/libc:shared_abi_interface"], target_compatible_with = _PLATFORM)
    for suffix in ([""] if interface == "atf" else ["", "_qualification"]):
        cc_binary(name = program + suffix, deps = [":" + program + "_link"],
            linkopts = ["-pie", "-nodefaultlibs"] + (["-Wl,--disable-new-dtags,-rpath,$ORIGIN"] if suffix else []),
            target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = [program], interfaces = {program: interface}, metadata = {program: metadata})
    bsd_install_file(name = "install_kyuafile", src = ":kyuafile", destination = directory + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    utility_installation(name = "install_manifest", program = program, manual = None, package = "tests", bindir = directory, extra_entries = [":install_kyuafile"])
    bsd_test_install_archive(name = "install_archive", directory = directory, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    if interface == "tap":
        bsd_kyua_test(name = "native_" + service.removeprefix("cap_"), program = ":" + program + "_qualification", interface = "tap",
            kyua = "@bsd_sdk//toolchain:extra_kyua", clean_environment = True,
            runtime = ["@bsd_sdk//toolchain:extra_kyua_runtime", "@bsd_sdk//toolchain:python_stdlib", "//tools/build/bazel:libmd_environment.py"],
            python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
            runtime_checker = "//tools/build/bazel:elf-runtime-check.py", runtime_libraries = {
                "//lib/libcasper/libcasper:casper_shared": "libcasper.so.1", package + ":" + service + "_shared": "lib" + service + ".so.1",
                "//lib/libnv:nv_shared": "libnv.so.1", "//lib/libc:c_shared": "libc.so.7", "//lib/libsys:sys_shared": "libsys.so.7"},
            test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, case_timeout = 300, timeout = "long", tags = ["external", "no-remote"], size = "medium", target_compatible_with = _PLATFORM)
        native.test_suite(name = "tests", tests = [":native_" + service.removeprefix("cap_")], visibility = ["//visibility:public"])
