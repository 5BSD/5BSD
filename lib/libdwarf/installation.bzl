# SPDX-License-Identifier: BSD-2-Clause
load(":installation_data.bzl", "MANUALS", "FORMAT_MANUALS", "MANUAL_LINKS")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def _manpath(name):
    return "/usr/share/man/man" + name.rsplit(".", 1)[1] + "/" + name + ".gz"

def dwarf_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":dwarf_shared",
        binary_name = name + "/libdwarf.so.4", debug_name = name + "/libdwarf.so.4.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libdwarf.so.4",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libdwarf.a", ["package=libdwarf", "dev"], False),
        (":" + name + "_stripped", "/usr/lib/libdwarf.so.4", ["package=libdwarf"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libdwarf.so.4.debug", ["package=libdwarf", "dbg"], False),
    ]
    for header in ["dwarf.h", "libdwarf.h"]:
        files.append(("//contrib/elftoolchain:libdwarf/" + header, "/usr/include/" + header, ["package=libdwarf", "dev"], False))
    for manual in MANUALS + FORMAT_MANUALS:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = "//contrib/elftoolchain:libdwarf/" + manual,
            output = name + "/" + manual + ".gz", arguments = ["-cn"],
            compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libdwarf-man"],
            "//conditions:default": ["package=libdwarf-dev" if manual in MANUALS else "package=libdwarf"]})
        files.append((":" + target, _manpath(manual), tags, True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    for original, alias in MANUAL_LINKS:
        target = name + "_alias_" + alias
        bsd_install_link(manual = True, name = target, destination = _manpath(alias), target = _manpath(original),
            kind = "hardlink", owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libdwarf-man"],
                "//conditions:default": ["package=libdwarf-dev"]}))
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libdwarf.so", target = "libdwarf.so.4",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libdwarf", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
