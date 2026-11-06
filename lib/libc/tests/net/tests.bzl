# SPDX-License-Identifier: BSD-2-Clause
"""Original network test inventory, C++20 ABI boundaries and installed fixtures."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import", "cc_library")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_script_wrapper")
load("//tools/build/bazel:bsd_sed_output.bzl", "bsd_sed_output")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_SOURCE = "//contrib/netbsd-tests/lib/libc/net:"
_DIRECTORY = "/usr/tests/lib/libc/net"
_CASES = {
    "ether_test": ["ether_line", "ether_line_bad_1", "ether_line_bad_2", "ether_aton_r", "ether_aton_r_bad", "ether_aton", "ether_aton_bad", "ether_ntoa_r", "ether_ntoa"],
    "eui64_aton_test": ["id_ascii", "id_colon_ascii", "mac_ascii", "mac_colon_ascii", "hex_ascii"],
    "eui64_ntoa_test": ["id_ascii"],
    "link_addr_test": ["basic", "ifname", "smallbuf", "invalid", "nonether", "overlong", "link_ntoa_r"],
    "inet_net_test": ["inet_net_inet4", "inet_net_inet6", "inet_net_pton_invalid", "inet_net_ntop_invalid"],
    "getprotoent_test": ["getprotobyname_basic", "getprotobyname_err", "getprotobynumber_basic", "getprotobynumber_err", "endprotoent_rewind", "getprotoent_next", "setprotoent_rewind"],
    "ether_aton_test": ["tc_ether_aton"],
}
_CXX_RUNTIME = ["//lib/atf/libatf-c++:atf_cxx_shared", "//lib/libc++:cxx_shared", "//lib/libcxxrt:cxxrt_shared", "//lib/msun:m_shared", "//lib/libgcc_s:gcc_s_shared"]

def network_tests():
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared", deps = ["//contrib/atf:c_headers"])
    cc_import(name = "atf_cxx_interface", shared_library = "//lib/atf/libatf-c++:atf_cxx_shared", deps = ["//contrib/atf:cxx_headers"])
    cc_import(name = "cxx_interface", shared_library = "//lib/libc++:cxx_shared", deps = ["//contrib/llvm-project/libcxx/include:headers"])
    for name, library in [("cxxrt", "//lib/libcxxrt:cxxrt_shared"), ("m", "//lib/msun:m_shared"), ("gcc_s", "//lib/libgcc_s:gcc_s_shared"), ("thr", "//lib/libthr:thr_shared")]:
        cc_import(name = name + "_interface", shared_library = library)
    cc_library(name = "eui64_headers", hdrs = ["test-eui64.h"], includes = ["."])
    manifests = []
    tests = []
    programs = {p: [p + ".c"] for p in ["ether_test", "eui64_aton_test", "eui64_ntoa_test"]}
    programs.update({p: [p + ".cc"] for p in ["link_addr_test", "inet_net_test"]})
    programs.update({"getprotoent_test": [_SOURCE + "t_getprotoent.c"], "ether_aton_test": [":aton_ether_subr", _SOURCE + "t_ether_aton.c"]})
    programs.update({p: [_SOURCE + p + ".c"] for p in ["h_nsd_recurse", "h_protoent", "h_servent", "h_dns_server"]})
    for program, sources in programs.items():
        atf = program in _CASES
        cxx = program in ["link_addr_test", "inet_net_test"]
        imported = program in ["getprotoent_test", "ether_aton_test"]
        deps = ([":atf_cxx_interface"] if cxx else []) + ([":atf_interface"] if atf else [])
        if imported:
            deps += ["//lib/libnetbsd:netbsd_pie", "//contrib/netbsd-tests:test_headers"]
        if program in ["eui64_aton_test", "eui64_ntoa_test"]:
            deps.append(":eui64_headers")
        if program == "h_nsd_recurse":
            deps.append(":thr_interface")
        if cxx:
            deps += [":cxx_interface", ":cxxrt_interface", ":m_interface", "//lib/libcompiler_rt:compiler_rt", ":gcc_s_interface"]
        deps.append("//lib/libc:shared_abi_interface")
        bsd_link_sequence(name = program + "_link", deps = deps)
        copts = libc_test_copts(2)
        if cxx:
            copts = [flag for flag in copts if flag not in ["-std=gnu17", "-Wno-pointer-sign"]] + ["-nostdinc++", "-std=c++20", "-Wno-c++20-extensions", "-Wno-c++23-lambda-attributes", "-Wno-nullability-completeness"]
        cc_binary(name = program, srcs = sources, deps = [":" + program + "_link"], copts = copts,
            defines = [] if cxx else ["PIC"], linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None, package = "tests", bindir = _DIRECTORY)
        manifests.append(":" + program + "_install")
        for case in _CASES.get(program, []):
            name = program + "_" + case + "_runtime"
            bsd_atf_test(name = name, body = ":" + program, case_name = case, interface = "program",
                runtime_lib = LIBC_TEST_RUNTIME + (_CXX_RUNTIME if cxx else []),
                test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, runner = "//tools/build/bazel:atf_runner",
                tags = ["external", "no-remote"] if program == "getprotoent_test" else [],
                target_compatible_with = _PLATFORM, size = "small")
            tests.append(":" + name)
    # These original shell cases read public host databases but only write their
    # private case directory. Keep host-sensitive outcomes out of remote/cache reuse.
    for program, body, case, helper in [
        ("nsdispatch_test", _SOURCE + "t_nsdispatch.sh", "recurse", "h_nsd_recurse"),
        ("protoent_test", _SOURCE + "t_protoent.sh", "protoent", "h_protoent"),
        ("servent_test", ":servent_body", "servent", "h_servent"),
    ]:
        name = program + "_" + case + "_runtime"
        bsd_atf_test(name = name, body = body, case_name = case,
            subr = "//libexec/atf/atf-sh:shell_library", data_paths = {":" + helper: helper},
            runtime_bin = ["//bin/sh:sh", "//bin/cat:cat", "//libexec/atf/atf-sh:atf-sh", "//libexec/atf/atf-check:atf-check", "//usr.bin/tr:tr", "//usr.bin/awk:awk", "//usr.bin/sort:sort", "//usr.bin/sed:sed", "//usr.bin/diff:diff", "//usr.bin/uname:uname", "//usr.bin/dirname:dirname"],
            runtime_lib = LIBC_TEST_RUNTIME + _CXX_RUNTIME + ["//lib/libthr:thr_shared", "//lib/libmd:md_shared", "//lib/libregex:regex_shared"],
            test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, runner = "//tools/build/bazel:atf_runner",
            tags = ["external", "no-remote"], target_compatible_with = _PLATFORM, size = "small")
        tests.append(":" + name)
    entries = []
    bsd_sed_output(name = "servent_body", template = _SOURCE + "t_servent.sh", output = "servent-body.sh",
        arguments = ["-e", "s,services.cdb,services.db,g"], sed = "@bsd_sdk//toolchain:sed",
        runtime = ["@bsd_sdk//toolchain:sed_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")
    for program, body in [("nsdispatch_test", _SOURCE + "t_nsdispatch.sh"), ("protoent_test", _SOURCE + "t_protoent.sh"), ("servent_test", ":servent_body")]:
        bsd_script_wrapper(name = program, body = body, interpreter = "/usr/libexec/atf-sh",
            cat = "@bsd_sdk//toolchain:cat", cat_runtime = ["@bsd_sdk//toolchain:cat_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")
        name = program + "_entry"
        bsd_install_file(name = name, src = ":" + program, destination = _DIRECTORY + "/" + program,
            owner = "root", group = "wheel", mode = "0555", install_tags = ["package=tests"])
        entries.append(":" + name)
    for name in ["hosts", "resolv.conf"]:
        bsd_install_file(name = name + "_entry", src = _SOURCE + name, destination = _DIRECTORY + "/" + name,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
        entries.append(":" + name + "_entry")
    names = sorted(_CASES.keys()) + ["nsdispatch_test", "protoent_test", "servent_test"]
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = names, interfaces = {p: "atf" for p in names}, subdirectories = ["getaddrinfo"])
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = entries + [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive", "//lib/libc/tests/net/getaddrinfo:installation_archives"], visibility = ["//visibility:public"], target_compatible_with = _PLATFORM)
    native.test_suite(name = "runtime_tests", tests = tests)
