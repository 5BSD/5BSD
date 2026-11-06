# SPDX-License-Identifier: BSD-2-Clause
"""Original selected AMD64 library ATF programs and installation contracts."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import", "cc_library")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_DIRECTORY = "/usr/tests/lib/librt"
_PROGRAMS = ['sched_test', 'sem_test']
_IMPORTED = ['sched_test', 'sem_test']

# Original metadata and reviewed host selection; unselected cases remain explicit
# manual targets for disposable guests, preserving privilege/cleanup/deadlines.
_CASES = {'sched_test': ['sched_getparam',
                'sched_priority',
                'sched_setscheduler_1',
                'sched_setscheduler_2',
                'sched_setscheduler_3',
                'sched_setscheduler_4',
                'sched_rr_get_interval_1',
                'sched_rr_get_interval_2'],
 'sem_test': ['basic',
              'child',
              'timedwait',
              'clockwait_monotonic_absolute',
              'clockwait_monotonic_relative',
              'clockwait_absolute_intr_remaining',
              'clockwait_relative_intr_remaining']}
_CLEANUP = {'sched_test': [], 'sem_test': ['basic', 'child']}
_USERS = {'sched_test': {'sched_setscheduler_1': 'root',
                'sched_setscheduler_2': 'root',
                'sched_setscheduler_3': 'root',
                'sched_setscheduler_4': 'root',
                'sched_rr_get_interval_1': 'root',
                'sched_rr_get_interval_2': 'root'},
 'sem_test': {}}
_TIMEOUTS = {'sched_test': {},
 'sem_test': {'child': 5,
              'timedwait': 20,
              'clockwait_monotonic_absolute': 20,
              'clockwait_monotonic_relative': 20,
              'clockwait_absolute_intr_remaining': 20,
              'clockwait_relative_intr_remaining': 20}}
_HOST_CASES = {'sched_test': ['sched_getparam', 'sched_priority'],
 'sem_test': ['timedwait',
              'clockwait_monotonic_absolute',
              'clockwait_monotonic_relative',
              'clockwait_absolute_intr_remaining',
              'clockwait_relative_intr_remaining']}

def library_tests():
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared", deps = ["//contrib/atf:c_headers"])
    cc_import(name = "rt_interface", shared_library = "//lib/librt:rt_shared", deps = [])
    manifests = []
    tests = []
    for program in _PROGRAMS:
        imported = program in _IMPORTED
        sources = ["//contrib/netbsd-tests/lib/librt:t_" + program.removesuffix("_test") + ".c" if imported else program + ".c"]
        deps = [":atf_interface"] + [':rt_interface']
        deps += (["//lib/libnetbsd:netbsd_pie", "//contrib/netbsd-tests:test_headers"] if imported else [])
        deps.append("//lib/libc:shared_abi_interface")
        bsd_link_sequence(name = program + "_link", deps = deps, target_compatible_with = _PLATFORM)
        cc_binary(name = program, srcs = sources, deps = [":" + program + "_link"],
            copts = libc_test_copts(warnings = 6), defines = ["PIC"],
            linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None,
            package = "tests", bindir = _DIRECTORY)
        manifests.append(":" + program + "_install")
        for case in _CASES[program]:
            selected = case in _HOST_CASES[program]
            target = program + "_" + case + "_runtime"
            bsd_atf_test(name = target, body = ":" + program + "_install_stripped", case_name = case, interface = "program",
                runtime_lib = LIBC_TEST_RUNTIME + ['//lib/librt:rt_shared', '//lib/libthr:thr_shared'],
                cleanup = case in _CLEANUP[program], required_user = _USERS[program].get(case, ""),
                body_timeout_seconds = _TIMEOUTS[program].get(case, 300),
                tags = ([] if selected else ["manual", "external", "no-remote"]),
                runner = "//tools/build/bazel:atf_runner", test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"},
                target_compatible_with = _PLATFORM, size = "small", timeout = "long")
            if selected:
                tests.append(":" + target)
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = sorted(_PROGRAMS), interfaces = {p: "atf" for p in _PROGRAMS})
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"],
        target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    native.test_suite(name = "runtime_tests", tests = tests)
