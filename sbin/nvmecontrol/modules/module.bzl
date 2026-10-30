# SPDX-License-Identifier: BSD-2-Clause
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_shared_library")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")

def nvme_module(name):
    cc_library(name = "objects", srcs = [name + ".c"], deps = ["//sbin/nvmecontrol:headers"], linkstatic = True,
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"])
    cc_shared_library(name = name, deps = [":objects"], shared_lib_name = name + ".so",
        user_link_flags = ["-Wl,-soname," + name + ".so", "-Wl,--fatal-warnings,--warn-shared-textrel"],
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"], visibility = ["//visibility:public"])
    bsd_debug_split(name = "debug", src = ":" + name, binary_name = "install/" + name + ".so", debug_name = "install/" + name + ".so.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = "stripped", src = ":debug", output = "install/stripped/" + name + ".so",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = "symbols", srcs = [":debug"], output_group = "debug_files")
    bsd_install_file(name = "module_install", src = ":stripped", destination = "/lib/nvmecontrol/" + name + ".so",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=nvme-tools"])
    bsd_install_file(name = "debug_install", src = ":symbols", destination = "/usr/lib/debug/lib/nvmecontrol/" + name + ".so.debug",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=nvme-tools", "dbg"])
    bsd_install_manifest(name = "install_manifest", entries = [":module_install", ":debug_install"], visibility = ["//visibility:public"])
