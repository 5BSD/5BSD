# SPDX-License-Identifier: BSD-2-Clause
"""Fresh account database payload; account migration is a separate operation."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

def account_installation():
    entries = []
    # Generated state matches Make and runtime.ucl construction actions.
    # Do not package prebuilt account databases over local configuration.
    for filename, group, mode in [("passwd", "passwd", "0644"), ("pwd.db", "pwd_db", "0644"), ("spwd.db", "spwd_db", "0600")]:
        name = "account_" + group
        native.filegroup(name = name, srcs = [":account_databases"], output_group = group)
        bsd_install_file(name = name + "_install", src = ":" + name,
            destination = "/etc/" + filename, owner = "root", group = "wheel",
            mode = mode, install_tags = [])
        entries.append(":" + name + "_install")
    bsd_install_manifest(name = "account_install_manifest", entries = entries, visibility = ["//lib/libc:__pkg__"])
    bsd_install_archive(name = "account_install_archive", manifests = [":account_install_manifest"],
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/"},
        passwd = ":master.passwd", group = ":group",
        mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"])
