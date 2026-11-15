# SPDX-License-Identifier: BSD-2-Clause
# Native descriptor test declarations; the remaining kern suite stays open.
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_manifest")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")

# Both Tier 1 platforms use native library interfaces; root cases run in VMs.
_PLATFORM = ["@platforms//os:freebsd"] + select({
    "@platforms//cpu:x86_64": [], "@platforms//cpu:aarch64": [],
    "//conditions:default": ["@platforms//:incompatible"],
})
_CASES = {
    "jaildesc": ["get_invalid_base_descriptor", "poll_close_race", "poll_remove_wakeup",
        "poll_close_race_get_desc", "curjail_get", "self_destruct", "at_desc_bad_fd"],
    "jaildesc_cap_test": ["cap_jail_set", "cap_jail_capmode", "cap_jail_attach",
        "cap_jail_remove", "cap_jail_both", "cap_jail_unlimited"],
}
_RUNTIME = {
    "jaildesc": LIBC_TEST_RUNTIME + ["//lib/libkvm:kvm_shared", "//lib/libelf:elf_shared", "//lib/libthr:thr_shared"],
    "jaildesc_cap_test": LIBC_TEST_RUNTIME + ["//lib/libjail:jail_shared"],
}

def descriptor_tests():
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared",
        deps = ["//contrib/atf:c_headers"])
    cc_import(name = "kvm_interface", shared_library = "//lib/libkvm:kvm_shared",
        deps = ["//lib/libkvm:headers"])
    cc_import(name = "pthread_interface", shared_library = "//lib/libthr:thr_shared")
    cc_import(name = "jail_interface", shared_library = "//lib/libjail:jail_shared",
        deps = ["//lib/libjail:headers"])

    manifests = []
    for program, cases in _CASES.items():
        deps = ([":kvm_interface", ":pthread_interface"] if program == "jaildesc" else
            [":jail_interface", "//tests:suite_macros"])
        bsd_link_sequence(name = program + "_link",
            deps = [":atf_interface"] + deps + ["//lib/libc:shared_abi_interface"],
            target_compatible_with = _PLATFORM)
        cc_binary(name = program, srcs = [program + ".c"], deps = [":" + program + "_link"],
            copts = libc_test_copts(warnings = 3), defines = ["PIC"],
            linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None,
            package = "tests", bindir = "/usr/tests/sys/kern")
        manifests.append(":" + program + "_install")
        for case in cases:
            host = program == "jaildesc" and case == "get_invalid_base_descriptor"
            bsd_atf_test(name = program + "_" + case + "_runtime", interface = "program",
                body = ":" + program + "_install_stripped", case_name = case,
                runner = "//tools/build/bazel:atf_runner", runtime_lib = _RUNTIME[program],
                required_user = "" if host else "root", cleanup = program == "jaildesc_cap_test",
                body_timeout_seconds = 300,
                tags = ["external", "no-remote"] + ([] if host else ["manual", "exclusive"]),
                target_compatible_with = _PLATFORM, size = "small", timeout = "long")

    # A partial contribution must not replace the complete directory's Kyuafile.
    bsd_install_manifest(name = "descriptor_install_manifest", manifests = manifests,
        visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "descriptor_install_archive", directory = "/usr/tests/sys/kern",
        manifests = [":descriptor_install_manifest"], debug = True,
        visibility = ["//tests:__pkg__"])
    native.test_suite(name = "descriptor_host_tests", tests = [":jaildesc_get_invalid_base_descriptor_runtime"],
        visibility = ["//visibility:public"])
