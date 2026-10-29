# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")


def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":sqlite3_shared",
        binary_name = name + "/libprivatesqlite3.so.0", debug_name = name + "/libprivatesqlite3.so.0.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libprivatesqlite3.so.0",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("//contrib/sqlite3:sqlite3.h", "/usr/include/private/sqlite3/sqlite3.h", ["package=libsqlite3", "dev"]),
        ("//contrib/sqlite3:sqlite3ext.h", "/usr/include/private/sqlite3/sqlite3ext.h", ["package=libsqlite3", "dev"]),
        (":static_archive", "/usr/lib/libprivatesqlite3.a", ["package=libsqlite3", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libprivatesqlite3.so.0", ["package=libsqlite3"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libprivatesqlite3.so.0.debug", ["package=libsqlite3", "dbg"]),
    ]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libprivatesqlite3.so", target = "libprivatesqlite3.so.0",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libsqlite3", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
