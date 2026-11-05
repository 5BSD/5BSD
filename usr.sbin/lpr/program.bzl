# SPDX-License-Identifier: BSD-2-Clause
"""Printing programs: explicit producers, original privilege metadata and payloads."""
load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

def printing_program(name, srcs, manual = "", man_section = "8", bindir = "/usr/sbin", common = True, edit = False, group = "wheel", mode = "0555", inet6 = True, extra_entries = [], extra_manifests = [], directories = {}):
    deps = ["//usr.sbin/lpr/common_source:headers"]
    if common:
        deps.append("//usr.sbin/lpr/common_source:lpr_pie")
    if edit:
        deps.append("//lib/libedit:edit")
    cc_binary(name = name, srcs = srcs, deps = deps,
        dynamic_deps = ["//lib/libedit:edit_shared"] if edit else [],
        local_defines = select({"//tools/build/bazel/config:inet6_support_enabled": ["INET6"], "//conditions:default": []}) if inet6 else [],
        copts = ["-fPIE"], linkopts = ["-pie"], linkstatic = True,
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"], visibility = ["//visibility:public"])
    utility_installation(name = "install_manifest", program = name, manual = manual, man_section = man_section,
        package = "lp", bindir = bindir, binary_group = group, binary_mode = mode, extra_entries = extra_entries)
    debug_directories = {}
    current = "/usr/lib/debug"
    for component in bindir.removeprefix("/").split("/"):
        current += "/" + component
        debug_directories[current] = '{"owner":"root","group":"wheel","mode":"0755","tags":["package=lp","dbg"]}'
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"] + extra_manifests,
        directories = debug_directories | directories,
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], visibility = ["//visibility:public"])
