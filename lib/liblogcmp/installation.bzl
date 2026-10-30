# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

MANUAL_ALIASES = ['logcmp_client_open', 'logcmp_logger_create', 'logcmp_logger_destroy', 'logcmp_emit', 'logcmp_log', 'logcmp_vlog', 'logcmp_flush', 'logcmp_stats', 'logcmp_query_next', 'logcmp_client_close']

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":logcmp_shared",
        binary_name = name + "/liblogcmp.so.1", debug_name = name + "/liblogcmp.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/liblogcmp.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("logcmp.h", "/usr/include/logcmp.h", ["package=liblogcmp", "dev"]),
        ("logcmp_protocol.h", "/usr/include/logcmp_protocol.h", ["package=liblogcmp", "dev"]),
        ("logcmp_server.h", "/usr/include/logcmp_server.h", ["package=liblogcmp", "dev"]),

        (":static_archive", "/usr/lib/liblogcmp.a", ["package=liblogcmp", "dev"]),
        (":" + name + "_stripped", "/usr/lib/liblogcmp.so.1", ["package=liblogcmp"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/liblogcmp.so.1.debug", ["package=liblogcmp", "dbg"]),
    ]
    bsd_compress(name = name + "_manual", src = "liblogcmp.3",
        output = name + "/liblogcmp.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/liblogcmp.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=liblogcmp-man"], "//conditions:default": ["package=liblogcmp-dev"]})))
    files.append(("logcmp.fidl", "/usr/share/fidl/logcmp.fidl", ["package=liblogcmp-dev"]))
    files += [("//contrib/fuchsia:" + n, "/usr/share/licenses/liblogcmp/fuchsia/" + n, ["package=liblogcmp"]) for n in ["LICENSE", "PATENTS"]]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/liblogcmp.so", target = "liblogcmp.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=liblogcmp", "dev"])
    for alias in MANUAL_ALIASES:
        target = name + "_manual_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/liblogcmp.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=liblogcmp-man"], "//conditions:default": ["package=liblogcmp-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
