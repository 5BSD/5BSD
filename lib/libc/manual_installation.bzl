# SPDX-License-Identifier: BSD-2-Clause
load(":manual_sources.bzl", "MANUALS", "MANUAL_LINKS")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")

def manual_installation(name):
    entries, iconv_entries = [], []
    for manual, source, runtime, iconv in MANUALS:
        compressed = name + "_compressed_" + manual
        bsd_compress(name = compressed, src = source, output = "manuals/" + manual + ".gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        target = name + "_file_" + manual
        tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=clibs-man"],
            "//conditions:default": ["package=clibs" if runtime else "package=clibs-dev"]})
        bsd_install_file(manual = True, name = target, src = ":" + compressed,
            destination = "/usr/share/man/man" + manual.split(".")[-1] + "/" + manual + ".gz",
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        (iconv_entries if iconv else entries).append(":" + target)
    for source, destination, iconv in MANUAL_LINKS:
        target = name + "_link_" + destination
        bsd_install_link(manual = True, name = target,
            destination = "/usr/share/man/man" + destination.split(".")[-1] + "/" + destination + ".gz",
            target = "/usr/share/man/man" + source.split(".")[-1] + "/" + source + ".gz",
            kind = "hardlink", owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=clibs-man"],
                "//conditions:default": ["package=clibs-dev"]}))
        (iconv_entries if iconv else entries).append(":" + target)
    bsd_install_manifest(name = name, entries = entries + select({
        "//tools/build/bazel/config:iconv_enabled": iconv_entries, "//conditions:default": []}),
        visibility = ["//visibility:public"])
