# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":blocklist_shared",
        binary_name = name + "/libblocklist.so.0", debug_name = name + "/libblocklist.so.0.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libblocklist.so.0",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libblocklist.a", ["package=blocklist", "dev"], False),
        (":" + name + "_stripped", "/usr/lib/libblocklist.so.0", ["package=blocklist", "lib"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libblocklist.so.0.debug", ["package=blocklist", "dbg"], False),
    ]
    files.append(("//contrib/blocklist:include/blocklist.h", "/usr/include/blocklist.h", ["package=blocklist", "dev"], False))
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=blocklist-man"], "//conditions:default": ["package=blocklist-dev"]})
    bsd_compress(name = name + "_manual", src = "//contrib/blocklist:lib/libblocklist.3", output = name + "/libblocklist.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libblocklist.3.gz", man_tags, True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libblocklist.so", target = "libblocklist.so.0",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=blocklist", "dev"])
    for alias in ["blocklist_open", "blocklist_close", "blocklist", "blocklist_r", "blocklist_sa", "blocklist_sa_r"]:
        target = name + "_alias_" + alias
        bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz", target = "/usr/share/man/man3/libblocklist.3.gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
