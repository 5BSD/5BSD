# SPDX-License-Identifier: BSD-2-Clause
"""Production-only libcasper payloads, independent of installed test selection."""
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

def casper_production_archive(name):
    bsd_install_archive(
        name = name,
        manifests = [":install_manifest"],
        target_compatible_with = select({
            "//tools/build/bazel/config:casper_enabled": [],
            "//conditions:default": ["@platforms//:incompatible"],
        }),
        directories = {"/usr/lib/debug/lib": '{"owner":"root","group":"wheel","mode":"0755","tags":["package=libcasper","dbg"]}'},
        mtree_specs = {
            "//etc/mtree:BSD.root.dist": "/",
            "//etc/mtree:BSD.usr.dist": "/usr",
            "//etc/mtree:BSD.include.dist": "/usr/include",
            "//etc/mtree:BSD.debug.dist": "/usr/lib",
        },
        passwd = "//etc:master.passwd",
        group = "//etc:group",
        mtree = "@bsd_sdk//toolchain:extra_mtree",
        epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python",
        python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"],
        visibility = ["//lib/libcasper:__subpackages__"],
    )
