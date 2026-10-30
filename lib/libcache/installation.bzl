# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":cache_shared",
        binary_name = name + "/libcache.so.1", debug_name = name + "/libcache.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libcache.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libcache.a", ["package=libcache", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libcache.so.1", ["package=libcache"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libcache.so.1.debug", ["package=libcache", "dbg"]),
    ]
    files.append(("bsd_cache.h", "/usr/include/bsd_cache.h", ["package=libcache", "dev"]))
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libcache-man"], "//conditions:default": ["package=libcache-dev"]})
    bsd_compress(name = name + "_manual", src = "bsd_cache.3", output = name + "/bsd_cache.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/bsd_cache.3.gz", man_tags))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libcache.so", target = "libcache.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libcache", "dev"])
    for function in ["open", "lookup", "generation", "put_if_current", "create", "put", "get", "remove", "purge", "set_limits", "set_pressure", "get_stats", "destroy"]:
        alias = name + "_manual_" + function
        bsd_install_link(name = alias, destination = "/usr/share/man/man3/bsd_cache_" + function + ".3.gz",
            target = "/usr/share/man/man3/bsd_cache.3.gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + alias)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
