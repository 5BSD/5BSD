# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

load(":install_inventory.bzl", "HEADERS", "MANUALS", "MANUAL_ALIASES")
load("//tools/build/bazel:bsd_compare_test.bzl", "bsd_filter_fixture")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":pcap_shared",
        binary_name = name + "/libpcap.so.8", debug_name = name + "/libpcap.so.8.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libpcap.so.8",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libpcap.a", ["package=utilities", "dev"], False),
        (":" + name + "_stripped", "/lib/libpcap.so.8", ["package=utilities"], False),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libpcap.so.8.debug", ["package=utilities", "dbg"], False),
    ]
    for header in HEADERS:
        files.append(("//contrib/libpcap:" + header, "/usr/include/" + header, ["package=utilities", "dev"], False))
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"], "//conditions:default": ["package=utilities-dev"]})
    for page, source, nodev in MANUALS:
        target = name + "_manual_" + page
        bsd_filter_fixture(name = target, src = "//contrib/libpcap:" + source, output = name + "/" + page,
            tool = "@bsd_sdk//toolchain:sed", arguments = ["-e", "s/3PCAP/3/g", "-e", "s/@MAN_FILE_FORMATS@/5/g", "-e", "s/@MAN_MISC_INFO@/7/g", "-e", "s/@MAN_ADMIN_COMMANDS@/8/g"],
            runtime = ["@bsd_sdk//toolchain:sed_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")
        bsd_compress(name = target + "_gz", src = ":" + target, output = name + "/" + page + ".gz", arguments = ["-cn"],
            compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"], "//conditions:default": ["package=utilities"]}) if nodev else man_tags
        files.append((":" + target + "_gz", "/usr/share/man/man" + page[-1] + "/" + page + ".gz", tags, True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libpcap.so", target = "../../lib/libpcap.so.8",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=utilities", "dev"])
    for source, alias in MANUAL_ALIASES:
        target = name + "_alias_" + alias
        bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man" + alias[-1] + "/" + alias + ".gz",
            target = "/usr/share/man/man" + source[-1] + "/" + source + ".gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
