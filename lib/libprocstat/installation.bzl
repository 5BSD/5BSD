# SPDX-License-Identifier: BSD-2-Clause
load(":installation_data.bzl", "HEADERS", "MANUALS", "MANUAL_LINKS")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def _manpath(manual):
    return "/usr/share/man/man" + manual.rsplit(".", 1)[1] + "/" + manual + ".gz"

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":procstat_shared",
        binary_name = name + "/libprocstat.so.1", debug_name = name + "/libprocstat.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libprocstat.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libprocstat.a", ["package=utilities", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libprocstat.so.1", ["package=utilities"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libprocstat.so.1.debug", ["package=utilities", "dbg"]),
    ] + [(header, "/usr/include/" + header, ["package=utilities", "dev"]) for header in HEADERS]
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"],
        "//conditions:default": ["package=utilities-dev"]})
    for manual in MANUALS:
        compressed = name + "_manual_" + manual
        bsd_compress(name = compressed, src = manual, output = name + "/" + manual + ".gz", arguments = ["-cn"],
            compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":" + compressed, _manpath(manual), man_tags))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libprocstat.so", target = "libprocstat.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=utilities", "dev"])
    entries.append(":" + name + "_link")
    for index, (source, destination) in enumerate(MANUAL_LINKS):
        target = name + "_manual_link_" + str(index)
        bsd_install_link(name = target, destination = _manpath(destination), target = _manpath(source),
            kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
