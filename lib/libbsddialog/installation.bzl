# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")


def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":bsddialog_shared",
        binary_name = name + "/libprivatebsddialog.so.0", debug_name = name + "/libprivatebsddialog.so.0.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libprivatebsddialog.so.0",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("//contrib/bsddialog/lib:bsddialog.h", "/usr/include/private/bsddialog/bsddialog.h", ["package=utilities", "dev"]),
("//contrib/bsddialog/lib:bsddialog_theme.h", "/usr/include/private/bsddialog/bsddialog_theme.h", ["package=utilities", "dev"]),
("//contrib/bsddialog/lib:bsddialog_progressview.h", "/usr/include/private/bsddialog/bsddialog_progressview.h", ["package=utilities", "dev"]),
        (":static_archive", "/usr/lib/libprivatebsddialog.a", ["package=utilities", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libprivatebsddialog.so.0", ["package=utilities"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libprivatebsddialog.so.0.debug", ["package=utilities", "dbg"]),
    ]
    bsd_compress(name = name + "_manual", src = "//contrib/bsddialog/lib:bsddialog.3",
        output = name + "/bsddialog.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/bsddialog.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"], "//conditions:default": ["package=utilities-dev"]})))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libprivatebsddialog.so", target = "libprivatebsddialog.so.0",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=utilities", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
