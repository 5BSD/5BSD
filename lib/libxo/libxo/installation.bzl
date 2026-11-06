# SPDX-License-Identifier: BSD-2-Clause
load(":installation_data.bzl", "MANUALS", "NONDEV_MANUALS", "MANUAL_LINKS")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def _manpath(name):
    return "/usr/share/man/man" + name.rsplit(".", 1)[1] + "/" + name + ".gz"

def xo_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":xo_shared",
        binary_name = name + "/libxo.so.0", debug_name = name + "/libxo.so.0.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libxo.so.0",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libxo.a", ["package=runtime", "dev"], False),
        (":" + name + "_stripped", "/lib/libxo.so.0", ["package=runtime"], False),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libxo.so.0.debug", ["package=runtime", "dbg"], False),
    ]
    for header in ["xo.h", "xo_encoder.h"]:
        files.append(("//contrib/libxo:libxo/" + header, "/usr/include/libxo/" + header, ["package=runtime", "dev"], False))
    for manual in MANUALS + NONDEV_MANUALS:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = "//contrib/libxo:libxo/" + manual,
            output = name + "/" + manual + ".gz", arguments = ["-cn"],
            compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"],
            "//conditions:default": ["package=runtime" if manual in NONDEV_MANUALS else "package=runtime-dev"]})
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
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"],
                "//conditions:default": ["package=runtime-dev"]}))
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libxo.so", target = "../../lib/libxo.so.0",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=runtime", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
