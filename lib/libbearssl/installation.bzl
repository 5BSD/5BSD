# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load(":sources.bzl", "PUBLIC_HEADERS")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":bearssl_shared",
        binary_name = name + "/libbearssl.so.5", debug_name = name + "/libbearssl.so.5.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libbearssl.so.5",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libbearssl.a", ["package=utilities", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libbearssl.so.5", ["package=utilities"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libbearssl.so.5.debug", ["package=utilities", "dbg"]),
    ]
    files += [("//contrib/bearssl:" + h, "/usr/include/" + h[len("inc/"):], ["package=utilities", "dev"]) for h in PUBLIC_HEADERS]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libbearssl.so", target = "libbearssl.so.5",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=utilities", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
