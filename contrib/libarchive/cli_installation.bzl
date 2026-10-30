# SPDX-License-Identifier: BSD-2-Clause
"""Shared installation transformations for libarchive's command-line tools."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def archive_cli_installation(name, program, alias, package, manual):
    bsd_debug_split(name = name + "_debug", src = ":" + program,
        binary_name = name + "/" + program, debug_name = name + "/" + program + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/" + program,
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    bsd_compress(name = name + "_manual", src = manual, output = name + "/" + program + ".1.gz",
        arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
        runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=" + package + "-man"],
        "//conditions:default": ["package=" + package]})
    entries = []
    for suffix, source, destination, mode, tags in [
        ("binary", ":" + name + "_stripped", "/usr/bin/" + program, "0555", ["package=" + package]),
        ("symbols_file", ":" + name + "_symbols", "/usr/lib/debug/usr/bin/" + program + ".debug", "0444", ["package=" + package, "dbg"]),
        ("manual_file", ":" + name + "_manual", "/usr/share/man/man1/" + program + ".1.gz", "0444", man_tags),
    ]:
        target = name + "_" + suffix
        bsd_install_file(name = target, src = source, destination = destination, owner = "root", group = "wheel", mode = mode, install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_alias", destination = "/usr/bin/" + alias, target = program,
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=" + package])
    bsd_install_link(name = name + "_manual_alias", destination = "/usr/share/man/man1/" + alias + ".1.gz",
        target = "/usr/share/man/man1/" + program + ".1.gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_alias", ":" + name + "_manual_alias"], visibility = ["//visibility:public"])
