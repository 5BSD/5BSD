# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

MANUAL_ALIASES = ['bsdfilesystem_connect', 'bsdfilesystem_adopt', 'bsdfilesystem_close', 'bsdfilesystem_request', 'bsdfilesystem_request_quota', 'bsdfilesystem_release', 'bsdfilesystem_destroy', 'bsdfilesystem_ping', 'bsdfilesystem_begin_session', 'bsdfilesystem_mount_dir']

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":bsdfilesystem_shared",
        binary_name = name + "/libbsdfilesystem.so.1", debug_name = name + "/libbsdfilesystem.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libbsdfilesystem.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("bsdfilesystem.h", "/usr/include/bsdfilesystem.h", ["package=runtime", "dev"]),
        (":static_archive", "/usr/lib/libbsdfilesystem.a", ["package=runtime", "dev"]),
        (":" + name + "_stripped", "/lib/libbsdfilesystem.so.1", ["package=runtime"]),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libbsdfilesystem.so.1.debug", ["package=runtime", "dbg"]),
    ]
    bsd_compress(name = name + "_manual", src = "libbsdfilesystem.3",
        output = name + "/bsdfilesystem.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libbsdfilesystem.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"], "//conditions:default": ["package=runtime-dev"]})))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libbsdfilesystem.so", target = "../../lib/libbsdfilesystem.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=runtime", "dev"])
    for alias in MANUAL_ALIASES:
        target = name + "_manual_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/libbsdfilesystem.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"], "//conditions:default": ["package=runtime-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
