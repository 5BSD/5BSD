# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":ipt_shared",
        binary_name = name + "/libipt.so.0", debug_name = name + "/libipt.so.0.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libipt.so.0",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":" + name + "_stripped", "/lib/libipt.so.0", ["package=libipt"]),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libipt.so.0.debug", ["package=libipt", "dbg"]),
    ]
    files.append((":static_archive", "/usr/lib/libipt.a", ["package=libipt", "dev"]))
    files.append((":public_header", "/usr/include/libipt/intel-pt.h", ["package=libipt", "dev"]))
    for header in ['libipt/internal/include/pt_cpu.h', 'libipt/internal/include/pt_last_ip.h', 'libipt/internal/include/pt_time.h', 'include/pt_compiler.h']:
        files.append(("//contrib/processor-trace:" + header, "/usr/include/libipt/" + header.split("/")[-1], ["package=libipt", "dev"]))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libipt.so", target = "../../lib/libipt.so.0",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libipt", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
