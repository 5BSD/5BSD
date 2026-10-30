# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":crypt_shared",
        binary_name = name + "/libcrypt.so.5", debug_name = name + "/libcrypt.so.5.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libcrypt.so.5",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_link_script", "/usr/lib/libcrypt.a", ["package=runtime", "dev"]),
        (":shared_link_script", "/usr/lib/libcrypt.so", ["package=runtime", "dev"]),
        (":static_archive", "/usr/lib/libcrypt_real.a", ["package=runtime", "dev"]),
        (":" + name + "_stripped", "/lib/libcrypt.so.5", ["package=runtime"]),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libcrypt.so.5.debug", ["package=runtime", "dbg"]),
    ]
    bsd_compress(name = name + "_manual", src = "crypt.3",
        output = name + "/crypt.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/crypt.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"], "//conditions:default": ["package=runtime-dev"]})))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", flags = "schg" if destination == "/lib/libcrypt.so.5" else "", install_tags = tags)
        entries.append(":" + target)
    for alias in ["crypt_get_format", "crypt_r", "crypt_set_format"]:
        target = name + "_manual_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/crypt.3.gz", kind = "hardlink", owner = "root", group = "wheel",
            mode = "0444", install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"], "//conditions:default": ["package=runtime-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
