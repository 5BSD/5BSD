# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



load(":sources.bzl", "PUBLIC_HEADERS")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":blemesh_shared",
        binary_name = name + "/libblemesh.so.1", debug_name = name + "/libblemesh.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libblemesh.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libblemesh.a", ["package=bluetooth", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libblemesh.so.1", ["package=bluetooth"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libblemesh.so.1.debug", ["package=bluetooth", "dbg"]),
    ]
    files.extend([(header, "/usr/include/" + header, ["package=bluetooth", "dev"]) for header in PUBLIC_HEADERS])
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=bluetooth-man"], "//conditions:default": ["package=bluetooth-dev"]})
    bsd_compress(name = name + "_manual", src = "libblemesh.3", output = name + "/libblemesh.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libblemesh.3.gz", man_tags))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libblemesh.so", target = "libblemesh.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=bluetooth", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
