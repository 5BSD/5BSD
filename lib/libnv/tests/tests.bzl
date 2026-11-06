# SPDX-License-Identifier: BSD-2-Clause
"""Original AMD64 non-ASan libnv C/C++ ATF and TAP test construction."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import", "cc_library")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_kyua.bzl", "bsd_kyua_tap_test")
load("//lib/libc:test_policy.bzl", "libc_test_copts", "libc_test_cxx_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_DIRECTORY = "/usr/tests/lib/libnv"
_ATF_C = ["nvlist_send_recv_test"]
_ATF_CXX = ["cnv_tests", "dnv_tests", "nv_array_tests", "nv_tests"]
_TAP = ["nvlist_add_test", "nvlist_append_test", "nvlist_exists_test", "nvlist_free_test", "nvlist_get_test", "nvlist_move_test"]

_CASES = {'nvlist_send_recv_test': ['nvlist_send_recv__send_nvlist__dgram',
                           'nvlist_send_recv__send_nvlist__stream',
                           'nvlist_send_recv__highfd',
                           'nvlist_send_recv__send_closed_fd__dgram',
                           'nvlist_send_recv__send_closed_fd__stream',
                           'nvlist_send_recv__send_many_fds__dgram',
                           'nvlist_send_recv__send_many_fds__stream',
                           'nvlist_send_recv__overflow_header_size',
                           'nvlist_send_recv__overflow_big_endian_size',
                           'nvlist_send_recv__overflow_little_endian_size',
                           'nvlist_send_recv__invalid_fd_size',
                           'nvlist_send_recv__overflow_fd_size'],
 'cnv_tests': ['cnvlist_get_bool',
               'cnvlist_get_bool_array',
               'cnvlist_get_number',
               'cnvlist_get_string',
               'cnvlist_get_nvlist',
               'cnvlist_get_descriptor',
               'cnvlist_get_binary',
               'cnvlist_get_number_array',
               'cnvlist_get_string_array',
               'cnvlist_get_nvlist_array',
               'cnvlist_get_descriptor_array',
               'cnvlist_take_bool',
               'cnvlist_take_number',
               'cnvlist_take_string',
               'cnvlist_take_nvlist',
               'cnvlist_take_binary',
               'cnvlist_take_bool_array',
               'cnvlist_take_number_array',
               'cnvlist_take_string_array',
               'cnvlist_take_nvlist_array',
               'cnvlist_free_bool',
               'cnvlist_free_number',
               'cnvlist_free_string',
               'cnvlist_free_nvlist',
               'cnvlist_free_binary',
               'cnvlist_free_bool_array',
               'cnvlist_free_number_array',
               'cnvlist_free_string_array',
               'cnvlist_free_nvlist_array'],
 'dnv_tests': ['dnvlist_get_bool__present',
               'dnvlist_get_bool__default_value',
               'dnvlist_get_number__present',
               'dnvlist_get_number__default_value',
               'dnvlist_get_string__present',
               'dnvlist_get_string__default_value',
               'dnvlist_get_nvlist__present',
               'dnvlist_get_nvlist__default_value',
               'dnvlist_get_binary__present',
               'dnvlist_get_binary__default_value',
               'dnvlist_take_bool__present',
               'dnvlist_take_bool__empty',
               'dnvlist_take_bool__default_value',
               'dnvlist_take_number__present',
               'dnvlist_take_number__empty',
               'dnvlist_take_number__default_value',
               'dnvlist_take_string__present',
               'dnvlist_take_string__empty',
               'dnvlist_take_string__default_value',
               'dnvlist_take_nvlist__present',
               'dnvlist_take_nvlist__empty',
               'dnvlist_take_nvlist__default_value',
               'dnvlist_take_binary__present',
               'dnvlist_take_binary__empty',
               'dnvlist_take_binary__default_value'],
 'nv_array_tests': ['nvlist_bool_array__basic',
                    'nvlist_string_array__basic',
                    'nvlist_descriptor_array__basic',
                    'nvlist_number_array__basic',
                    'nvlist_nvlist_array__basic',
                    'nvlist_clone_array',
                    'nvlist_bool_array__move',
                    'nvlist_string_array__move',
                    'nvlist_nvlist_array__move',
                    'nvlist_number_array__move',
                    'nvlist_descriptor_array__move',
                    'nvlist_arrays__error_null',
                    'nvlist_arrays__bad_value',
                    'nvlist_nvlist_array__travel',
                    'nvlist_nvlist_array__travel_alternative',
                    'nvlist_bool_array__pack',
                    'nvlist_number_array__pack',
                    'nvlist_descriptor_array__pack',
                    'nvlist_string_array__pack',
                    'nvlist_nvlist_array__pack',
                    'nvlist_string_array_nonull__pack'],
 'nv_tests': ['nvlist_create__is_empty',
              'nvlist_add_null__single_insert',
              'nvlist_add_bool__single_insert',
              'nvlist_add_number__single_insert',
              'nvlist_add_string__single_insert',
              'nvlist_add_nvlist__single_insert',
              'nvlist_add_nvlist__child_with_error',
              'nvlist_add_binary__single_insert',
              'nvlist_clone__empty_nvlist',
              'nvlist_clone__nonempty_nvlist',
              'nvlist_clone__nested_nvlist',
              'nvlist_clone__error_nvlist',
              'nvlist_pack__empty_nvlist',
              'nvlist_pack__multiple_values',
              'nvlist_pack__error_nvlist',
              'nvlist_unpack__duplicate_key',
              'nvlist_unpack__flags_nvlist',
              'nvlist_move_string__single_insert',
              'nvlist_move_nvlist__single_insert',
              'nvlist_move_nvlist__null_child',
              'nvlist_move_nvlist__child_with_error',
              'nvlist_move_binary__single_insert',
              'nvlist_take_bool__single_remove',
              'nvlist_take_bool__other_keys_unchanged',
              'nvlist_take_number__single_remove',
              'nvlist_take_number__other_keys_unchanged',
              'nvlist_take_string__single_remove',
              'nvlist_take_string__other_keys_unchanged',
              'nvlist_take_nvlist__single_remove',
              'nvlist_take_nvlist__other_keys_unchanged',
              'nvlist_take_binary__single_remove',
              'nvlist_take_binary__other_keys_unchanged',
              'nvlist_free__single_null',
              'nvlist_free__single_bool',
              'nvlist_free__single_number',
              'nvlist_free__single_string',
              'nvlist_free__single_nvlist',
              'nvlist_free__single_binary',
              'nvlist_free_null__single_null',
              'nvlist_free_bool__single_bool',
              'nvlist_free_number__single_number',
              'nvlist_free_string__single_string',
              'nvlist_free_nvlist__single_nvlist',
              'nvlist_free_binary__single_binary']}
# Original case writes global datagram sysctls; execute only in a disposable guest.
_DEFERRED = {'nvlist_send_recv_test': ['nvlist_send_recv__send_many_fds__dgram']}

def nv_tests():
    for name, library, headers in [
        ("atf", "//lib/atf/libatf-c:atf_c_shared", ["//contrib/atf:c_headers"]),
        ("atf_cxx", "//lib/atf/libatf-c++:atf_cxx_shared", ["//contrib/atf:cxx_headers"]),
        ("nv", "//lib/libnv:nv_shared", ["//sys/sys:nv_headers"]),
        ("cxx", "//lib/libc++:cxx_shared", ["//contrib/llvm-project/libcxx/include:headers"]),
        ("cxxrt", "//lib/libcxxrt:cxxrt_shared", []),
        ("m", "//lib/msun:m_shared", []), ("gcc_s", "//lib/libgcc_s:gcc_s_shared", []),
    ]:
        cc_import(name = name + "_interface", shared_library = library, deps = headers)
    manifests = []
    tests = []
    atf_tests = []
    for program in _ATF_C + _ATF_CXX + _TAP:
        cxx = program in _ATF_CXX
        tap = program in _TAP
        sources = [program + (".cc" if cxx else ".c")]
        deps = ([":atf_cxx_interface"] if cxx else []) + ([] if tap else [":atf_interface"]) + [":nv_interface"]
        if cxx:
            deps += [":cxx_interface", ":cxxrt_interface", ":m_interface", "//lib/libcompiler_rt:compiler_rt", ":gcc_s_interface"]
        if program == "nvlist_send_recv_test":
            sources.append("//lib/libnv:msgio.c")
            deps += ["//lib/libnv:internal_headers", "//sys/contrib/libnv:user_test_headers"]
        deps += ["//lib/libc:shared_abi_interface"]
        flags = libc_test_cxx_copts(3) if cxx else libc_test_copts(3)
        definitions = ["PIC"] + (["NO_ASAN"] if program == "nvlist_send_recv_test" else [])
        if tap:
            # Both final links consume the same declared native objects. Only
            # the runtime-only link has a private inherited library search path.
            cc_library(name = program + "_objects", srcs = sources, deps = deps,
                copts = flags, defines = definitions, target_compatible_with = _PLATFORM)
            bsd_link_sequence(name = program + "_link", object_groups = [":" + program + "_objects"], deps = deps)
            for suffix in ["", "_qualification"]:
                cc_binary(name = program + suffix, deps = [":" + program + "_link"],
                    linkopts = ["-pie", "-nodefaultlibs"] + (["-Wl,--disable-new-dtags,-rpath,$ORIGIN"] if suffix else []),
                    target_compatible_with = _PLATFORM)
            target = program + "_runtime"
            bsd_kyua_tap_test(name = target, program = ":" + program + "_qualification", program_path = program,
                kyua = "@bsd_sdk//toolchain:extra_kyua", clean_environment = True,
                runtime = ["@bsd_sdk//toolchain:extra_kyua_runtime", "@bsd_sdk//toolchain:python_stdlib", "//tools/build/bazel:libmd_environment.py"],
                python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
                runtime_checker = "//tools/build/bazel:elf-runtime-check.py",
                runtime_libraries = {"//lib/libnv:nv_shared": "libnv.so.1", "//lib/libc:c_shared": "libc.so.7", "//lib/libsys:sys_shared": "libsys.so.7"},
                test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, case_timeout = 300, size = "small", timeout = "long", target_compatible_with = _PLATFORM)
            tests.append(":" + target)
        else:
            bsd_link_sequence(name = program + "_link", deps = deps)
            cc_binary(name = program, srcs = sources, deps = [":" + program + "_link"],
                copts = flags, defines = definitions, linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None, package = "tests", bindir = _DIRECTORY)
        manifests.append(":" + program + "_install")
        if not tap:
            for case in _CASES[program]:
                selected = case not in _DEFERRED.get(program, [])
                target = program + "_" + case + "_runtime"
                bsd_atf_test(name = target, body = ":" + program + "_install_stripped", case_name = case, interface = "program",
                    runtime_lib = LIBC_TEST_RUNTIME + ["//lib/libnv:nv_shared"] + (["//lib/atf/libatf-c++:atf_cxx_shared", "//lib/libc++:cxx_shared", "//lib/libcxxrt:cxxrt_shared", "//lib/msun:m_shared", "//lib/libgcc_s:gcc_s_shared"] if cxx else []),
                    runner = "//tools/build/bazel:atf_runner", test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"},
                    tags = [] if selected else ["manual", "external", "no-remote"],
                    body_timeout_seconds = 300, target_compatible_with = _PLATFORM, size = "small", timeout = "long")
                if selected:
                    atf_tests.append(":" + target)
    programs = sorted(_ATF_C + _ATF_CXX + _TAP)
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = programs,
        interfaces = {p: "tap" if p in _TAP else "atf" for p in programs})
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    native.test_suite(name = "tap_runtime_tests", tests = tests)
    native.test_suite(name = "atf_runtime_tests", tests = atf_tests)
