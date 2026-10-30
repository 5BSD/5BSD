# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":veriexec_shared",
        binary_name = name + "/libveriexec.so.5", debug_name = name + "/libveriexec.so.5.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libveriexec.so.5",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libveriexec.a", ["package=utilities", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libveriexec.so.5", ["package=utilities"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libveriexec.so.5.debug", ["package=utilities", "dbg"]),
    ]
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"], "//conditions:default": ["package=utilities-dev"]})
    bsd_compress(name = name + "_manual", src = "veriexec.3", output = name + "/veriexec.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/veriexec.3.gz", man_tags))
    files.append(("libveriexec.h", "/usr/include/libveriexec.h", ["package=utilities", "dev"]))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libveriexec.so", target = "libveriexec.so.5",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=utilities", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
