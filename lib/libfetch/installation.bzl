# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

load(":installation_data.bzl", "MANUALS", "MANUAL_LINKS")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":fetch_shared",
        binary_name = name + "/libfetch.so.6", debug_name = name + "/libfetch.so.6.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libfetch.so.6",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("fetch.h", "/usr/include/fetch.h", ["package=fetch", "dev"]),
        (":static_archive", "/usr/lib/libfetch.a", ["package=fetch", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libfetch.so.6", ["package=fetch"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libfetch.so.6.debug", ["package=fetch", "dbg"]),
    ]
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=fetch-man"], "//conditions:default": ["package=fetch-dev"]})
    for manual in MANUALS:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = manual, output = name + "/" + manual + ".gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":" + target, "/usr/share/man/man3/" + manual + ".gz", man_tags))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libfetch.so", target = "libfetch.so.6",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=fetch", "dev"])
    for source, alias in MANUAL_LINKS:
        target = name + "_manual_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".gz",
            target = "/usr/share/man/man3/" + source + ".gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=fetch-man"], "//conditions:default": ["package=fetch-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
