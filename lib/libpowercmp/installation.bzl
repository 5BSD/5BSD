# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

MANUAL_ALIASES = ["powercmp_client_open", "powercmp_client_close", "powercmp_states", "powercmp_suspend", "powercmp_client_create", "powercmp_inhibit", "powercmp_uninhibit", "powercmp_inhibitors"]

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":powercmp_shared",
        binary_name = name + "/libpowercmp.so.1", debug_name = name + "/libpowercmp.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libpowercmp.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("powercmp.h", "/usr/include/powercmp.h", ["package=libpowercmp", "dev"], False),
        ("powercmp_protocol.h", "/usr/include/powercmp_protocol.h", ["package=libpowercmp", "dev"], False),

        (":static_archive", "/usr/lib/libpowercmp.a", ["package=libpowercmp", "dev"], False),
        (":" + name + "_stripped", "/usr/lib/libpowercmp.so.1", ["package=libpowercmp"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libpowercmp.so.1.debug", ["package=libpowercmp", "dbg"], False),
    ]
    bsd_compress(name = name + "_manual", src = "libpowercmp.3",
        output = name + "/libpowercmp.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libpowercmp.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libpowercmp-man"], "//conditions:default": ["package=libpowercmp-dev"]}), True))
    files.append(("powercmp.fidl", "/usr/share/fidl/powercmp.fidl", ["package=libpowercmp-dev"], False))
    files += [("//contrib/fuchsia:" + n, "/usr/share/licenses/libpowercmp/fuchsia/" + n, ["package=libpowercmp"], False) for n in ["LICENSE", "PATENTS"]]
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libpowercmp.so", target = "libpowercmp.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libpowercmp", "dev"])
    for alias in MANUAL_ALIASES:
        target = name + "_manual_" + alias
        bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/libpowercmp.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libpowercmp-man"], "//conditions:default": ["package=libpowercmp-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
