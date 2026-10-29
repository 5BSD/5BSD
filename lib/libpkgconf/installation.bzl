# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")


def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":pkgconf_shared",
        binary_name = name + "/libprivatepkgconf.so.5", debug_name = name + "/libprivatepkgconf.so.5.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libprivatepkgconf.so.5",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("//contrib/pkgconf:libpkgconf/libpkgconf.h", "/usr/include/private/pkgconf/libpkgconf.h", ["package=pkgconf", "dev"]),
        ("//contrib/pkgconf:libpkgconf/stdinc.h", "/usr/include/private/pkgconf/stdinc.h", ["package=pkgconf", "dev"]),
        ("//contrib/pkgconf:libpkgconf/iter.h", "/usr/include/private/pkgconf/iter.h", ["package=pkgconf", "dev"]),
        ("//contrib/pkgconf:libpkgconf/bsdstubs.h", "/usr/include/private/pkgconf/bsdstubs.h", ["package=pkgconf", "dev"]),
        ("//contrib/pkgconf:libpkgconf/libpkgconf-api.h", "/usr/include/private/pkgconf/libpkgconf-api.h", ["package=pkgconf", "dev"]),
        (":static_archive", "/usr/lib/libprivatepkgconf.a", ["package=pkgconf", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libprivatepkgconf.so.5", ["package=pkgconf"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libprivatepkgconf.so.5.debug", ["package=pkgconf", "dbg"]),
    ]
    for manual in ["pkg.m4.7", "pc.5", "pkgconf-personality.5"]:
        section = manual[-1]
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = "//contrib/pkgconf:man/" + manual,
            output = name + "/" + manual + ".gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":" + target, "/usr/share/man/man" + section + "/" + manual + ".gz",
            select({"//tools/build/bazel/config:split_manpages_enabled": ["package=pkgconf-man"], "//conditions:default": ["package=pkgconf-dev" if manual == "pkg.m4.7" else "package=pkgconf"]})))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libprivatepkgconf.so", target = "libprivatepkgconf.so.5",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=pkgconf", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
