# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":com_err_shared",
        binary_name = name + "/libcom_err.so.5", debug_name = name + "/libcom_err.so.5.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libcom_err.so.5",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libcom_err.a", ["package=kerberos", "dev"], False),
        (":" + name + "_stripped", "/usr/lib/libcom_err.so.5", ["package=kerberos", "lib"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libcom_err.so.5.debug", ["package=kerberos", "dbg"], False),
    ]
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=kerberos-man"], "//conditions:default": ["package=kerberos-dev"]})
    bsd_compress(name = name + "_manual", src = "//contrib/com_err:com_err.3", output = name + "/com_err.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/com_err.3.gz", man_tags, True))
    for header in ["com_err.h", "com_right.h"]:
        files.append(("//contrib/com_err:" + header, "/usr/include/" + header, ["package=kerberos", "dev"], False))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libcom_err.so", target = "libcom_err.so.5",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=kerberos", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
