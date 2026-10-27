# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":wrap_shared",
        binary_name = name + "/libwrap.so.6", debug_name = name + "/libwrap.so.6.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libwrap.so.6",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libwrap.a", ["package=tcpd", "dev"], "0444"),
        (":" + name + "_stripped", "/usr/lib/libwrap.so.6", ["package=tcpd"], "0444"),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libwrap.so.6.debug", ["package=tcpd", "dbg"], "0444"),
        ("//contrib/tcp_wrappers:tcpd.h", "/usr/include/tcpd.h", ["package=tcpd", "dev"], "0444"),
        ("hosts.allow", "/etc/hosts.allow", ["package=tcpd", "config"], "0644"),
    ]
    dev_man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=tcpd-man"], "//conditions:default": ["package=tcpd-dev"]})
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=tcpd-man"], "//conditions:default": ["package=tcpd"]})
    for manual in ["hosts_access.3", "hosts_access.5", "hosts_options.5"]:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = "//contrib/tcp_wrappers:" + manual, output = name + "/" + manual + ".gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":" + target, "/usr/share/man/man" + manual[-1] + "/" + manual + ".gz", dev_man_tags if manual[-1] == "3" else man_tags, "0444"))
    entries = []
    for source, destination, tags, mode in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = mode, install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libwrap.so", target = "libwrap.so.6",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=tcpd", "dev"])
    for alias, manual in {"hosts_ctl.3": "hosts_access.3", "request_init.3": "hosts_access.3", "request_set.3": "hosts_access.3", "hosts.allow.5": "hosts_options.5"}.items():
        target = name + "_alias_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man" + alias[-1] + "/" + alias + ".gz", target = "/usr/share/man/man" + manual[-1] + "/" + manual + ".gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = dev_man_tags if alias[-1] == "3" else man_tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
