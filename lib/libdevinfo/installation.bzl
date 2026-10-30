# SPDX-License-Identifier: BSD-2-Clause
load(":installation_data.bzl", "MANUALS", "MANUAL_LINKS")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def _manpath(name):
    return "/usr/share/man/man" + name.rsplit(".", 1)[1] + "/" + name + ".gz"

def devinfo_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":devinfo_shared",
        binary_name = name + "/libdevinfo.so.7", debug_name = name + "/libdevinfo.so.7.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libdevinfo.so.7",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libdevinfo.a", ["package=devmatch", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libdevinfo.so.7", ["package=devmatch"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libdevinfo.so.7.debug", ["package=devmatch", "dbg"]),
    ]
    files.append(("devinfo.h", "/usr/include/devinfo.h", ["package=devmatch", "dev"]))
    for manual in MANUALS:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = manual,
            output = name + "/" + manual + ".gz", arguments = ["-cn"],
            compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=devmatch-man"],
            "//conditions:default": ["package=devmatch-dev"]})
        files.append((":" + target, _manpath(manual), tags))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    for original, alias in MANUAL_LINKS:
        target = name + "_alias_" + alias
        bsd_install_link(name = target, destination = _manpath(alias), target = _manpath(original),
            kind = "hardlink", owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=devmatch-man"],
                "//conditions:default": ["package=devmatch-dev"]}))
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libdevinfo.so", target = "libdevinfo.so.7",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=devmatch", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
