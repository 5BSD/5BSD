# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":gcc_s_asneeded_shared",
        binary_name = name + "/libgcc_s_asneeded.so.1", debug_name = name + "/libgcc_s_asneeded.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libgcc_s_asneeded.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":" + name + "_stripped", "/lib/libgcc_s_asneeded.so.1", ["package=clibs"]),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libgcc_s_asneeded.so.1.debug", ["package=clibs", "dbg"]),
    ]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_file(name = name + "_script", src = ":linker_script", destination = "/usr/lib/libgcc_s_asneeded.so", owner = "root", group = "wheel", mode = "0444", install_tags = ["package=clibs", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_script"], visibility = ["//visibility:public"])
