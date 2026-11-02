# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")
def dwatch_archive(name, manifests, directories):
    bsd_install_archive(name = name, manifests = manifests,
        directories = {path: json.encode({"owner": "root", "group": "wheel", "mode": "0755", "tags": ["package=dwatch"]}) for path in directories},
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree",
        epoch = 0, python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"],
        visibility = ["//visibility:public"])
