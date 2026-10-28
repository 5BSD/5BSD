# SPDX-License-Identifier: BSD-2-Clause
"""Installation of flua loadable modules and their split debug files."""
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")

def module_installation(name, module, binary = ":module", extra_entries = []):
    bsd_debug_split(name = name + "_debug", src = binary,
        binary_name = name + "/" + module, debug_name = name + "/" + module + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/" + module,
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    bsd_install_file(name = name + "_file", src = ":" + name + "_stripped", destination = "/usr/lib/flua/" + module,
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=flua"])
    bsd_install_file(name = name + "_debug_file", src = ":" + name + "_symbols", destination = "/usr/lib/debug/usr/lib/flua/" + module + ".debug",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=flua", "dbg"])
    bsd_install_manifest(name = name, entries = [":" + name + "_file", ":" + name + "_debug_file"] + extra_entries, visibility = ["//libexec/flua:__pkg__"])
