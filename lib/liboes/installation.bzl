# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

MANUAL_ALIASES = []

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":oes_shared",
        binary_name = name + "/liboes.so.1", debug_name = name + "/liboes.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/liboes.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("liboes.h", "/usr/include/liboes.h", ["package=oes", "dev"], False),

        ("//sys/security/oes:oes.h", "/usr/include/security/oes/oes.h", ["package=oes", "dev"], False),
        ("//sys/security/oes:oes_event_table.h", "/usr/include/security/oes/oes_event_table.h", ["package=oes", "dev"], False),
        (":static_archive", "/usr/lib/liboes.a", ["package=oes", "dev"], False),
        (":" + name + "_stripped", "/usr/lib/liboes.so.1", ["package=oes"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/liboes.so.1.debug", ["package=oes", "dbg"], False),
    ]
    bsd_compress(name = name + "_manual", src = "liboes.3",
        output = name + "/liboes.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/liboes.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=oes-man"], "//conditions:default": ["package=oes-dev"]}), True))
    files.append(("oes_broker.fidl", "/usr/share/fidl/oes_broker.fidl", ["package=oes"], False))
    files += [("//contrib/fuchsia:" + n, "/usr/share/licenses/liboes/fuchsia/" + n, ["package=oes"], False) for n in ["LICENSE", "PATENTS"]]
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/liboes.so", target = "liboes.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=oes", "dev"])
    for alias in MANUAL_ALIASES:
        target = name + "_manual_" + alias
        bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/liboes.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=oes-man"], "//conditions:default": ["package=oes-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
