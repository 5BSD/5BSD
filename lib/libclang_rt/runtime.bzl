# SPDX-License-Identifier: BSD-2-Clause
"""Native amd64 compiler-rt static-library policy from Makefile.inc.

Callers own explicit source inventories and extra component definitions. PIC
objects form the single installed archive; this does not enable instrumentation
of the runtime itself or imply runtime qualification.
"""
load("@rules_cc//cc:defs.bzl", "cc_library")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_archive", "bsd_component_sources")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

_COPTS = ["-fno-builtin", "-fno-exceptions", "-fno-sanitize=safe-stack", "-fno-stack-protector", "-funwind-tables"]
_CXXOPTS = ["-std=c++17"] + _COPTS + ["-fno-rtti", "-fvisibility-inlines-hidden", "-fvisibility=hidden"]
_DEFINES = ["NDEBUG", "HAVE_RPC_XDR_H=0", "SANITIZER_SUPPORTS_WEAK_HOOKS=0", "UBSAN_CAN_USE_CXXABI"]
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]

def compiler_rt_archive(stem, cxx_srcs, deps, asm_srcs = [], defines = []):
    cc_library(name = "objects", srcs = cxx_srcs, deps = deps,
        copts = _CXXOPTS, local_defines = _DEFINES + defines,
        target_compatible_with = _PLATFORM)
    groups = [":objects"]
    if asm_srcs:
        cc_library(name = "assembly", srcs = asm_srcs, deps = deps,
            copts = _COPTS, local_defines = _DEFINES + defines,
            target_compatible_with = _PLATFORM)
        groups.append(":assembly")
    bsd_component_archive(name = "static_archive", groups = groups, pic = True,
        visibility = ["//visibility:public"])
    bsd_component_sources(name = "source_inventory", groups = groups,
        visibility = ["//visibility:public"])
    bsd_install_file(name = "archive_file", src = ":static_archive",
        destination = "/usr/lib/clang/21/lib/freebsd/libclang_rt." + stem + "-x86_64.a",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=clang", "dev"])
    bsd_install_manifest(name = "install_manifest", entries = [":archive_file"], visibility = ["//visibility:public"])
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"],
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"],
        visibility = ["//visibility:public"])
