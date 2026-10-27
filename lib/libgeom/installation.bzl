# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

load(":installation_data.bzl", "MANUAL_ALIASES")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":geom_shared",
        binary_name = name + "/libgeom.so.5", debug_name = name + "/libgeom.so.5.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libgeom.so.5",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("libgeom.h", "/usr/include/libgeom.h", ["package=runtime", "dev"]),
        (":static_archive", "/usr/lib/libgeom.a", ["package=runtime", "dev"]),
        (":" + name + "_stripped", "/lib/libgeom.so.5", ["package=runtime"]),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libgeom.so.5.debug", ["package=runtime", "dbg"]),
    ]
    bsd_compress(name = name + "_manual", src = "libgeom.3",
        output = name + "/libgeom.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libgeom.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"], "//conditions:default": ["package=runtime-dev"]})))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libgeom.so", target = "../../lib/libgeom.so.5",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=runtime", "dev"])
    for alias in MANUAL_ALIASES:
        target = name + "_manual_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/libgeom.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"], "//conditions:default": ["package=runtime-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
