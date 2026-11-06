# SPDX-License-Identifier: BSD-2-Clause
load(":installation_data.bzl", "MANUALS", "MANUAL_LINKS")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def _manpath(name):
    return "/usr/share/man/man" + name.rsplit(".", 1)[1] + "/" + name + ".gz"

def ufs_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":ufs_shared",
        binary_name = name + "/libufs.so.8", debug_name = name + "/libufs.so.8.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libufs.so.8",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libufs.a", ["package=ufs", "dev"], False),
        (":" + name + "_stripped", "/lib/libufs.so.8", ["package=ufs", "lib"], False),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libufs.so.8.debug", ["package=ufs", "dbg"], False),
    ]
    files.append(("libufs.h", "/usr/include/libufs.h", ["package=ufs", "dev"], False))
    for manual in MANUALS:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = manual,
            output = name + "/" + manual + ".gz", arguments = ["-cn"],
            compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=ufs-man"],
            "//conditions:default": ["package=ufs-dev"]})
        files.append((":" + target, _manpath(manual), tags, True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    for original, alias in MANUAL_LINKS:
        target = name + "_alias_" + alias
        bsd_install_link(manual = True, name = target, destination = _manpath(alias), target = _manpath(original),
            kind = "hardlink", owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=ufs-man"],
                "//conditions:default": ["package=ufs-dev"]}))
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libufs.so", target = "../../lib/libufs.so.8",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=ufs", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
