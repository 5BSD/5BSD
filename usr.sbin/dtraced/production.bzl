# SPDX-License-Identifier: BSD-2-Clause
"""Original dtraced C++ daemon: native sources, options and installation."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load("@bazel_skylib//lib:selects.bzl", "selects")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_directory", "bsd_install_manifest")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

_WARNINGS = [
    "-Wall", "-Wextra", "-Wno-c11-extensions", "-Wsystem-headers", "-Wno-format-y2k",
    "-W", "-Wno-unused-parameter", "-Wpointer-arith", "-Wno-uninitialized", "-Wdate-time",
    "-Wno-empty-body", "-Wno-string-plus-int", "-Wno-unused-const-variable",
    "-Wno-error=unused-but-set-parameter", "-Wno-error=cast-function-type-mismatch",
    "-Wno-tautological-compare", "-Wno-unused-value", "-Wno-parentheses-equality",
    "-Wno-unused-function", "-Wno-enum-conversion", "-Wno-unused-local-typedef",
    "-Wno-address-of-packed-member", "-Wno-gcc-compat", "-Wno-gnu-anonymous-struct",
    "-Wno-zero-length-array", "-Wno-c99-designator", "-Wno-c++20-extensions",
    "-Wno-c++23-lambda-attributes", "-Wno-nullability-completeness",
]
# Make emits its pthread link option after the other explicit LIBADD entries.
_LIBS = ["//cddl/lib/libctf:ctf", "//lib/libelf:elf", "//lib/libproc:proc",
         "//secure/lib/libcrypto:crypto", "//lib/libutil:util", "//lib/libcxxrt:cxxrt", "//lib/libthr:thr",
         "//lib/libc++:cxx", "//lib/msun:m"]
_SHARED = ["//cddl/lib/libctf:ctf_shared", "//lib/libelf:elf_shared", "//lib/libproc:proc_shared",
           "//secure/lib/libcrypto:crypto_shared", "//lib/libutil:util_shared", "//lib/libcxxrt:cxxrt_shared", "//lib/libthr:thr_shared",
           "//lib/libc++:cxx_shared", "//lib/msun:m_shared"]

def dtraced_production():
    # One compilation context permits mutually including source sys headers.
    # Absolute workspace stripping preserves Make's -I sys include spellings.
    cc_library(name = "source_kernel_headers", hdrs = ["//sys/amd64/include:dtraced_userland_headers", "//sys/bsm:dtraced_userland_headers", "//sys/dev/vmm:dtraced_userland_headers", "//sys/sys:dtraced_userland_headers"],
        strip_include_prefix = "/sys")
    # This candidate rejects other architectures rather than enabling LTO on
    # Make-excluded platforms such as RISC-V. Cross-platform closure is pending.
    native.config_setting(name = "lto_arch", constraint_values = ["@platforms//cpu:x86_64"])
    selects.config_setting_group(name = "lto_enabled", match_all = ["//tools/build/bazel/config:dtrace_optimized_enabled", ":lto_arch"])
    lto = select({":lto_enabled": ["-flto"], "//conditions:default": []})
    native.config_setting(name = "tsan_without_asan", flag_values = {
        "//tools/build/bazel/config:dtraced_asan": "false",
        "//tools/build/bazel/config:dtraced_tsan": "true",
    })
    sanitize = select({
        "//tools/build/bazel/config:dtraced_asan_enabled": ["-fsanitize=address", "-fsanitize=undefined"],
        ":tsan_without_asan": ["-fsanitize=thread"],
        "//conditions:default": [],
    })
    robust = select({"//tools/build/bazel/config:dtraced_robust_enabled": [
        "-DDTRACED_ROBUST", "-Wall", "-Wextra", "-ggdb3", "-Werror", "-Wpedantic",
        "-Wno-gnu-include-next", "-Wno-nullability-extension", "-Wno-gnu-empty-struct", "-fcxx-exceptions",
    ], "//conditions:default": []})
    cc_binary(
        name = "dtraced",
        srcs = ["dtraced.cc", "dtraced_child_ledger.cc", "dtraced_clientrequest.cc", "dtraced_connection.cc",
                "dtraced_directory.cc", "dtraced_dttransport.cc", "dtraced_errmsg.cc", "dtraced_job.cc",
                "dtraced_misc.cc", "dtraced_process.cc", "dtraced_state.cc"] + native.glob(["*.h"]),
        deps = _LIBS + ["//sys/dev/dttransport:userland_headers", ":source_kernel_headers"],
        dynamic_deps = _SHARED,
        copts = ["-nostdinc++", "-std=c++17", "-fPIE", "-pipe", "-fno-common", "-Qunused-arguments", "-Wno-format-zero-length"] +
            _WARNINGS + lto + sanitize + robust + ["-g", "-gz=zlib"] +
            select({"//tools/build/bazel/config:dtraced_debug_enabled": ["-DDTRACED_DEBUG"], "//conditions:default": []}) +
            select({"//tools/build/bazel/config:werror_enabled": ["-Werror"], "//conditions:default": []}),
        linkopts = ["-pie", "-Wl,-z,now", "-Wl,-z,relro"] + lto + sanitize,
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"],
        visibility = ["//visibility:public"],
    )
    native.filegroup(name = "source_objects", srcs = [":dtraced"], output_group = "compilation_outputs", visibility = ["//visibility:public"])
    utility_installation(name = "program_install", program = "dtraced", manual = "dtraced.8", package = "utilities", bindir = "/usr/sbin", man_section = "8")
    entries = []
    for index, directory in enumerate(["/usr/lib/debug/usr", "/usr/lib/debug/usr/sbin"]):
        name = "debug_directory_" + str(index)
        bsd_install_directory(name = name, destination = directory,
            owner = "root", group = "wheel", mode = "0755", install_tags = ["package=utilities", "dbg"])
        entries.append(":" + name)
    bsd_install_manifest(name = "install_manifest", manifests = [":program_install"], entries = entries, visibility = ["//visibility:public"])
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"],
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], visibility = ["//visibility:public"])
