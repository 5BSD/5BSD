# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":ctf_shared",
        binary_name = name + "/libctf.so.2", debug_name = name + "/libctf.so.2.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libctf.so.2",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libctf.a", ["package=ctf", "dev"]),
        (":" + name + "_stripped", "/lib/libctf.so.2", ["package=ctf", "lib"]),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libctf.so.2.debug", ["package=ctf", "dbg"]),
    ]
    bsd_compress(name = name + "_manual", src = "//cddl/contrib/opensolaris:lib/libctf/common/ctf.5",
        output = name + "/ctf.5.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man5/ctf.5.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=ctf-man"], "//conditions:default": ["package=ctf-dev"]})))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libctf.so", target = "../../lib/libctf.so.2",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=ctf", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
