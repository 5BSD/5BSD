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

_COPTS = ["-fpic", "-fno-builtin", "-fno-exceptions", "-fno-sanitize=safe-stack", "-fno-stack-protector", "-funwind-tables"]
_CXXOPTS = ["-std=c++17"] + _COPTS + ["-fno-rtti", "-fvisibility-inlines-hidden", "-fvisibility=hidden"]
_DEFINES = ["NDEBUG", "HAVE_RPC_XDR_H=0", "SANITIZER_SUPPORTS_WEAK_HOOKS=0", "UBSAN_CAN_USE_CXXABI"]
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]

def compiler_rt_objects(name, cxx_srcs, deps, defines = [], cxxopts = []):
    cc_library(name = name, srcs = cxx_srcs, deps = deps,
        copts = _CXXOPTS + cxxopts, local_defines = _DEFINES + defines,
        target_compatible_with = _PLATFORM)

def compiler_rt_archive(stem, cxx_srcs, deps, asm_srcs = [], defines = [], cxxopts = [], data_files = {}, installed_headers = {}, object_order = []):
    compiler_rt_objects(name = "objects", cxx_srcs = cxx_srcs, deps = deps,
        defines = defines, cxxopts = cxxopts)
    groups = [":objects"]
    if asm_srcs:
        cc_library(name = "assembly", srcs = asm_srcs, deps = deps,
            copts = _COPTS, local_defines = _DEFINES + defines,
            target_compatible_with = _PLATFORM)
        groups.append(":assembly")
    # Make compiles ordinary objects with -fpic, without the toolchain PIC
    # variant's -DPIC (which changes ASAN_DYNAMIC semantics).
    bsd_component_archive(name = "static_archive", groups = groups, pic = False, object_order = object_order,
        visibility = ["//visibility:public"])
    bsd_component_sources(name = "source_inventory", groups = groups,
        visibility = ["//visibility:public"])
    bsd_install_file(name = "archive_file", src = ":static_archive",
        destination = "/usr/lib/clang/21/lib/freebsd/libclang_rt." + stem + "-x86_64.a",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=clang", "dev"])
    entries = [":archive_file"]
    for index, (source, destination) in enumerate(data_files.items()):
        name = "data_" + str(index)
        bsd_install_file(name = name, src = source,
            destination = "/usr/lib/clang/21/share/" + destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=clang"])
        entries.append(":" + name)
    for index, (source, destination) in enumerate(installed_headers.items()):
        name = "header_" + str(index)
        bsd_install_file(name = name, src = source,
            destination = "/usr/lib/clang/21/include/" + destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=clang", "dev"])
        entries.append(":" + name)
    bsd_install_manifest(name = "install_manifest", entries = entries, visibility = ["//visibility:public"])
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"],
        directories = {"/usr/lib/clang/21/share": json.encode(dict(owner = "root", group = "wheel", mode = "0755", tags = ["package=clang"]))} if data_files else {},
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"],
        visibility = ["//visibility:public"])
