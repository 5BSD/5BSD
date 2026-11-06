# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":bsdconf_shared",
        binary_name = name + "/libbsdconf.so.1", debug_name = name + "/libbsdconf.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libbsdconf.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libbsdconf.a", ["package=utilities", "dev"], False),
        (":" + name + "_stripped", "/usr/lib/libbsdconf.so.1", ["package=utilities"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libbsdconf.so.1.debug", ["package=utilities", "dbg"], False),
    ]
    files.append(("bsdconf.h", "/usr/include/bsdconf.h", ["package=utilities", "dev"], False))
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"], "//conditions:default": ["package=utilities-dev"]})
    for manual in ["bsdconf.3", "bsdconf_format.3", "bsdconf_put.3"]:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = manual, output = name + "/" + manual + ".gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":" + target, "/usr/share/man/man3/" + manual + ".gz", man_tags, True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libbsdconf.so", target = "libbsdconf.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=utilities", "dev"])
    aliases = {
        "bsdconf.3": ["bsdconf_fparse", "bsdconf_get_option", "bsdconf_parse", "bsdconf_spool", "bsdconf_unquote"],
        "bsdconf_format.3": ["bsdconf_format_derive", "bsdconf_format_files", "bsdconf_format_files_free", "bsdconf_format_find", "bsdconf_format_guess", "bsdconf_format_lookup", "bsdconf_format_path", "bsdconf_format_processing", "bsdconf_format_put", "bsdconf_format_register"],
        "bsdconf_put.3": ["bsdconf_set_option"],
    }
    for original, names in aliases.items():
        for alias in names:
            target = name + "_alias_" + alias
            bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
                target = "/usr/share/man/man3/" + original + ".gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
            entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
