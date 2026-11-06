# SPDX-License-Identifier: BSD-2-Clause
"""Original AMD64 process-debugging test and dynamic/static child helpers."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_DIRECTORY = "/usr/tests/lib/libproc"
_PROGRAMS = ["proc_test", "target_prog", "target_prog_static"]
_LIBRARIES = [
    ("elf", "//lib/libelf", "elf_shared", ["//contrib/elftoolchain:elf_headers"]),
    ("proc", "//lib/libproc", "proc_shared", ["//lib/libproc:headers"]),
    ("rtld_db", "//lib/librtld_db", "rtld_db_shared", ["//lib/librtld_db:headers"]),
    ("util", "//lib/libutil", "util_shared", []),
    ("thr", "//lib/libthr", "thr_shared", []),
]

_CASES = ['map_alias_name2map',
 'static_symbol_lookup',
 'map_prefix_name2map',
 'map_alias_name2sym',
 'symbol_lookup',
 'symbol_lookup_fail',
 'signal_forward',
 'symbol_sort_local',
 'symbol_sort_prefix',
 'symbol_sort_underscore']
_RUNTIME = ['//lib/libc:c_shared',
 '//lib/libsys:sys_shared',
 '//lib/atf/libatf-c:atf_c_shared',
 '//lib/libelf:elf_shared',
 '//lib/libproc:proc_shared',
 '//lib/librtld_db:rtld_db_shared',
 '//lib/libutil:util_shared',
 '//lib/libthr:thr_shared',
 '//lib/libcxxrt:cxxrt_shared',
 '//lib/libprocstat:procstat_shared',
 '//lib/libz:z_shared',
 '//lib/libkvm:kvm_shared',
 '//lib/libnv:nv_shared',
 '//lib/libgcc_s:gcc_s_shared']

def proc_tests():
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared", deps = ["//contrib/atf:c_headers"])
    for name, package, library, headers in _LIBRARIES:
        cc_import(name = name + "_interface", shared_library = package + ":" + library, deps = headers)
    manifests = []
    for program in _PROGRAMS:
        static = program == "target_prog_static"
        helper = program != "proc_test"
        deps = ([] if helper else [":atf_interface"]) + [package + ":" + name if static else ":" + name + "_interface" for name, package, _, _ in _LIBRARIES]
        deps += ["//lib/libc:static_link_objects" if static else "//lib/libc:shared_abi_interface"]
        bsd_link_sequence(name = program + "_link", deps = deps, target_compatible_with = _PLATFORM)
        cc_binary(name = program, srcs = ["target_prog.c" if helper else "proc_test.c"], deps = [":" + program + "_link"],
            copts = [f for f in libc_test_copts(warnings = 6) if not static or f != "-fPIE"] + (["-O0"] if helper else []),
            defines = [] if static else ["PIC"], linkopts = ["-nodefaultlibs"] + (["-static"] if static else ["-pie"]),
            features = ["fully_static_link"] if static else [], linkstatic = True, target_compatible_with = _PLATFORM)
        # Original STRIP= preserves local/weak/strong symbols used by lookup tests.
        utility_installation(name = program + "_install", program = program, manual = None,
            package = "tests", bindir = _DIRECTORY, strip_symbols = False)
        manifests.append(":" + program + "_install")
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = ["proc_test"], interfaces = {"proc_test": "atf"})
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    tests = []
    for case in _CASES:
        target = case + "_runtime"
        bsd_atf_test(name = target, body = ":proc_test_install_stripped", case_name = case, interface = "program",
            data_paths = {":target_prog_install_stripped": "target_prog", ":target_prog_static_install_stripped": "target_prog_static"},
            runtime_lib = _RUNTIME, runner = "//tools/build/bazel:atf_runner",
            test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, tags = ["external", "no-remote"],
            body_timeout_seconds = 300, target_compatible_with = _PLATFORM, size = "small", timeout = "long")
        tests.append(":" + target)
    native.test_suite(name = "runtime_tests", tests = tests)
