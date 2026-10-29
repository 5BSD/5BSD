# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":begemot_shared",
        binary_name = name + "/libbegemot.so.4", debug_name = name + "/libbegemot.so.4.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libbegemot.so.4",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libbegemot.a", ["package=libbegemot", "dev"]),
        (":" + name + "_stripped", "/lib/libbegemot.so.4", ["package=libbegemot"]),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libbegemot.so.4.debug", ["package=libbegemot", "dbg"]),
    ]
    files.append(("//contrib/libbegemot:rpoll.h", "/usr/include/rpoll.h", ["package=libbegemot", "dev"]))
    bsd_compress(name = name + "_manual", src = "//contrib/libbegemot:rpoll.man",
        output = name + "/rpoll.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    manual_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libbegemot-man"], "//conditions:default": ["package=libbegemot-dev"]})
    files.append((":" + name + "_manual", "/usr/share/man/man3/rpoll.3.gz", manual_tags))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libbegemot.so", target = "../../lib/libbegemot.so.4",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libbegemot", "dev"])
    for alias in ["poll_register", "poll_unregister", "poll_start_timer", "poll_stop_timer", "poll_dispatch"]:
        target = name + "_alias_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/rpoll.3.gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = manual_tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
