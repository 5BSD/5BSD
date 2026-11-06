# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load(":installation_data.bzl", "MANUALS", "MANUAL_LINKS")

def zfs_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":zfs", binary_name = name + "/zfs", debug_name = name + "/zfs.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/zfs",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    entries = []
    for suffix, source, dest, mode, tags in [
        ("binary", ":" + name + "_stripped", "/sbin/zfs", "0555", ["package=zfs"]),
        ("symbols", ":" + name + "_symbols", "/usr/lib/debug/sbin/zfs.debug", "0444", ["package=zfs", "dbg"]),
    ]:
        target = name + "_file_" + suffix
        bsd_install_file(name = target, src = source, destination = dest, owner = "root", group = "wheel", mode = mode, install_tags = tags)
        entries.append(":" + target)
    tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=zfs-man"], "//conditions:default": ["package=zfs"]})
    for manual in MANUALS:
        section = manual.split(".")[-1]
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = "//sys/contrib/openzfs:man/man" + section + "/" + manual, output = name + "/" + manual + ".gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        bsd_install_file(manual = True, name = target + "_file", src = ":" + target, destination = "/usr/share/man/man" + section + "/" + manual + ".gz",
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target + "_file")
    for source, alias in MANUAL_LINKS:
        target = name + "_alias_" + alias
        bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man" + alias.split(".")[-1] + "/" + alias + ".gz",
            target = "/usr/share/man/man" + source.split(".")[-1] + "/" + source + ".gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
