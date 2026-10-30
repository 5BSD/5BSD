# SPDX-License-Identifier: BSD-2-Clause
"""Native liblzma installation inventory; xz programs are separate payloads."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
HEADERS = ["lzma.h"] + ["lzma/" + name + ".h" for name in [
    "base", "bcj", "block", "check", "container", "delta", "filter", "hardware",
    "index", "index_hash", "lzma12", "stream_flags", "version", "vli",
]]

def lzma_installation(name):
    native.filegroup(name = name + "_archive", srcs = [":lzma"], output_group = "archive")
    native.filegroup(name = name + "_debug", srcs = [":debug"], output_group = "debug_files")
    files = [
        ("archive", ":" + name + "_archive", "/usr/lib/liblzma.a", ["package=xz", "dev"]),
        ("shared", ":stripped", "/usr/lib/liblzma.so.5", ["package=xz", "lib"]),
        ("symbols", ":" + name + "_debug", "/usr/lib/debug/usr/lib/liblzma.so.5.debug", ["package=xz", "dbg"]),
        ("pkgconfig", ":pkgconfig", "/usr/libdata/pkgconfig/liblzma.pc", ["package=xz", "dev"]),
    ]
    for header in HEADERS:
        files.append(("header_" + header.replace("/", "_"), "//contrib/xz:src/liblzma/api/" + header,
            "/usr/include/" + header, ["package=xz", "dev"]))
    entries = []
    for suffix, source, destination, tags in files:
        entry = name + "_file_" + suffix
        bsd_install_file(name = entry, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + entry)
    entry = name + "_link"
    bsd_install_link(name = entry, destination = "/usr/lib/liblzma.so", target = "liblzma.so.5",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=xz", "dev"])
    entries.append(":" + entry)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
