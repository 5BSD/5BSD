# SPDX-License-Identifier: BSD-2-Clause
"""Common program artifacts and installation; callers own package and alias membership."""
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load("//tools/build/bazel:bsd_base_install.bzl", "bsd_program_install")
load("//tools/build/bazel:bsd_install.bzl", "bsd_compress", "bsd_install_file", "bsd_install_link")

def bsd_command_installation(name, program, manual, package, aliases = [], manual_aliases = []):
    bsd_debug_split(name = "debug", src = ":" + program,
        binary_name = "install/" + program, debug_name = "install/" + program + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = "stripped", src = ":debug", output = "stripped/" + program,
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    bsd_compress(name = "manual", src = manual, output = program + ".1.gz", arguments = ["-cn"],
        compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
        runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=" + package + "-man"],
        "//conditions:default": ["package=" + package]})
    bsd_install_file(manual = True, name = "manual_entry", src = ":manual", destination = "/usr/share/man/man1/" + program + ".1.gz",
        owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
    entries = [":manual_entry"]
    for kind, names, prefix, suffix, mode, tags in [
        ("bin", aliases, "/usr/bin/", "", "0555", ["package=" + package]),
        ("man", manual_aliases, "/usr/share/man/man1/", ".1.gz", "0444", man_tags),
    ]:
        for alias in names:
            entry = kind + "_link_" + alias
            bsd_install_link(manual = kind == "man", name = entry, destination = prefix + alias + suffix,
                target = prefix + program + suffix, kind = "hardlink", owner = "root",
                group = "wheel", mode = mode, install_tags = tags)
            entries.append(":" + entry)
    bsd_program_install(name = name, binary = ":stripped", debug = ":debug",
        destination = "/usr/bin/" + program, package = package, extra_entries = entries,
        visibility = ["//visibility:public"])
