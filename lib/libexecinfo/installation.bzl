# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":execinfo_shared",
        binary_name = name + "/libexecinfo.so.1", debug_name = name + "/libexecinfo.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libexecinfo.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("//contrib/libexecinfo:execinfo.h", "/usr/include/execinfo.h", ["package=libexecinfo", "dev"]),
        (":static_archive", "/usr/lib/libexecinfo.a", ["package=libexecinfo", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libexecinfo.so.1", ["package=libexecinfo"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libexecinfo.so.1.debug", ["package=libexecinfo", "dbg"]),
    ]
    bsd_compress(name = name + "_manual", src = "//contrib/libexecinfo:backtrace.3",
        output = name + "/backtrace.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/backtrace.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libexecinfo-man"], "//conditions:default": ["package=libexecinfo-dev"]})))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libexecinfo.so", target = "libexecinfo.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libexecinfo", "dev"])
    for alias in ["backtrace_symbols", "backtrace_symbols_fmt", "backtrace_symbols_fd", "backtrace_symbols_fd_fmt"]:
        target = name + "_manual_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/backtrace.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libexecinfo-man"], "//conditions:default": ["package=libexecinfo-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
