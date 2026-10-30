# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":usbhid_shared",
        binary_name = name + "/libusbhid.so.4", debug_name = name + "/libusbhid.so.4.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libusbhid.so.4",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libusbhid.a", ["package=utilities", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libusbhid.so.4", ["package=utilities"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libusbhid.so.4.debug", ["package=utilities", "dbg"]),
    ]
    files.append(("usbhid.h", "/usr/include/usbhid.h", ["package=utilities", "dev"]))
    bsd_compress(name = name + "_manual", src = "usbhid.3", output = name + "/usbhid.3.gz", arguments = ["-cn"],
        compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/usbhid.3.gz", select({"//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"], "//conditions:default": ["package=utilities-dev"]})))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libusbhid.so", target = "libusbhid.so.4",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=utilities", "dev"])
    for alias in ['libusbhid', 'hid_get_report_desc', 'hid_dispose_report_desc', 'hid_start_parse', 'hid_end_parse', 'hid_get_item', 'hid_report_size', 'hid_locate', 'hid_usage_page', 'hid_usage_in_page', 'hid_init', 'hid_get_data', 'hid_set_data']:
        target = name + "_man_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz", target = "/usr/share/man/man3/usbhid.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444", install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"], "//conditions:default": ["package=utilities-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
