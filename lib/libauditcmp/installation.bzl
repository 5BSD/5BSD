# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

MANUAL_ALIASES = ["auditcmp_client_open", "auditcmp_client_prepare", "auditcmp_client_adopt", "auditcmp_submit", "auditcmp_stats", "auditcmp_client_close"]

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":auditcmp_shared",
        binary_name = name + "/libauditcmp.so.1", debug_name = name + "/libauditcmp.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libauditcmp.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("auditcmp.h", "/usr/include/auditcmp.h", ["package=libauditcmp", "dev"]),
        ("auditcmp_protocol.h", "/usr/include/auditcmp_protocol.h", ["package=libauditcmp", "dev"]),
        ("auditcmp_server.h", "/usr/include/auditcmp_server.h", ["package=libauditcmp", "dev"]),

        (":static_archive", "/usr/lib/libauditcmp.a", ["package=libauditcmp", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libauditcmp.so.1", ["package=libauditcmp"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libauditcmp.so.1.debug", ["package=libauditcmp", "dbg"]),
    ]
    bsd_compress(name = name + "_manual", src = "libauditcmp.3",
        output = name + "/libauditcmp.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libauditcmp.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libauditcmp-man"], "//conditions:default": ["package=libauditcmp-dev"]})))
    files.append(("auditcmp.fidl", "/usr/share/fidl/auditcmp.fidl", ["package=libauditcmp-dev"]))
    files += [("//contrib/fuchsia:" + n, "/usr/share/licenses/libauditcmp/fuchsia/" + n, ["package=libauditcmp"]) for n in ["LICENSE", "PATENTS"]]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libauditcmp.so", target = "libauditcmp.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libauditcmp", "dev"])
    for alias in MANUAL_ALIASES:
        target = name + "_manual_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/libauditcmp.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libauditcmp-man"], "//conditions:default": ["package=libauditcmp-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
