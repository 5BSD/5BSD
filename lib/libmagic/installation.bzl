# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



load(":magic_configuration.bzl", "magic_database_install")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":magic_shared",
        binary_name = name + "/libmagic.so.4", debug_name = name + "/libmagic.so.4.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libmagic.so.4",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":magic_header", "/usr/include/magic.h", ["package=libmagic", "dev"]),
        (":pkgconfig", "/usr/libdata/pkgconfig/libmagic.pc", ["package=libmagic", "dev"]),
        (":static_archive", "/usr/lib/libmagic.a", ["package=libmagic", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libmagic.so.4", ["package=libmagic"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libmagic.so.4.debug", ["package=libmagic", "dbg"]),
    ]
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libmagic-man"], "//conditions:default": ["package=libmagic-dev"]})
    bsd_compress(name = name + "_manual", src = ":libmagic_manual", output = name + "/libmagic.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libmagic.3.gz", man_tags))
    bsd_compress(name = name + "_magic_manual", src = ":magic_manual", output = name + "/magic.5.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_magic_manual", "/usr/share/man/man5/magic.5.gz", select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libmagic-man"], "//conditions:default": ["package=libmagic"]})))
    magic_database_install(name = name + "_database_directory", configuration = ":configuration")
    entries = [":" + name + "_database_directory"]
    for basename, source in [("magic", ":magic_source"), ("magic.mgc", ":magic_compiled")]:
        target = name + "_database_" + basename
        magic_database_install(name = target, configuration = ":configuration", src = source, basename = basename)
        entries.append(":" + target)
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libmagic.so", target = "libmagic.so.4",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libmagic", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
