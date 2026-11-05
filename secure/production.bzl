# SPDX-License-Identifier: BSD-2-Clause
"""Explicit secure-family composition and component archive serialization."""
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive", "bsd_install_archive_set")

def production_archives(archives):
    bsd_install_archive_set(name = "production_installation_archives", archives = archives,
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"] + select({
            "//tools/build/bazel/config:tests_enabled": ["@platforms//:incompatible"], "//conditions:default": []}),
        visibility = ["//visibility:public"])

def component_archive(name, manifests):
    bsd_install_archive(name = name, manifests = manifests,
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.include.dist": "/usr/include", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"],
        visibility = ["//secure:__subpackages__"])
