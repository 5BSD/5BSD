# SPDX-License-Identifier: BSD-2-Clause
"""Declared OpenSSL installation transformations shared by its components."""
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load("//tools/build/bazel:bsd_install.bzl", "bsd_compress", "bsd_install_file", "bsd_install_link")

def openssl_file(name, source, destination, tags, mode = "0444"):
    bsd_install_file(name = name, src = source, destination = destination,
        owner = "root", group = "wheel", mode = mode, install_tags = tags)
    return ":" + name

def openssl_binary_entries(name, source, destination, program = False):
    basename = destination.rsplit("/", 1)[1]
    bsd_debug_split(name = name + "_debug", src = source,
        binary_name = name + "/" + basename, debug_name = name + "/" + basename + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/" + basename,
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    return [
        openssl_file(name + "_binary", ":" + name + "_stripped", destination,
            ["package=openssl"] + ([] if program else ["lib"]), "0555" if program else "0444"),
        openssl_file(name + "_debug_file", ":" + name + "_symbols", "/usr/lib/debug" + destination + ".debug",
            ["package=openssl", "dbg"]),
    ]

def openssl_manual_entries(name, manuals, aliases, development = False):
    tags = select({
        "//tools/build/bazel/config:split_manpages_enabled": ["package=openssl-man"],
        "//conditions:default": ["package=openssl-dev" if development else "package=openssl"],
    })
    entries = []
    for manual, source in manuals:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = source, output = name + "/" + manual + ".gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        entries.append(openssl_file(target + "_file", ":" + target, _manpath(manual), tags))
    for alias, original in aliases:
        target = name + "_alias_" + alias
        bsd_install_link(name = target, destination = _manpath(alias), target = _manpath(original),
            kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    return entries

def _manpath(manual):
    return "/usr/share/openssl/man/man" + manual.rsplit(".", 1)[1] + "/" + manual + ".gz"
