# SPDX-License-Identifier: BSD-2-Clause
"""Installed LLVM/Clang private shared libraries (no installed static archive)."""
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")

def compiler_shared_installation(name, library, major, binary, package = "clang"):
    soname = "libprivate" + library + ".so." + str(major)
    bsd_debug_split(name = name + "_debug", src = binary,
        binary_name = name + "/" + soname, debug_name = name + "/" + soname + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/" + soname,
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    bsd_install_file(name = name + "_library", src = ":" + name + "_stripped", destination = "/usr/lib/" + soname,
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=" + package])
    bsd_install_file(name = name + "_symbols_file", src = ":" + name + "_symbols", destination = "/usr/lib/debug/usr/lib/" + soname + ".debug",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=" + package, "dbg"])
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libprivate" + library + ".so", target = soname,
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=" + package, "dev"])
    bsd_install_manifest(name = name, entries = [":" + name + "_library", ":" + name + "_symbols_file", ":" + name + "_link"], visibility = ["//visibility:public"])
