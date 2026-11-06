# SPDX-License-Identifier: BSD-2-Clause

load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def _manpath(name):
    return "/usr/share/man/man" + name.rsplit(".", 1)[1] + "/" + name + ".gz"

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":sdp_shared",
        binary_name = name + "/libsdp.so.4", debug_name = name + "/libsdp.so.4.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libsdp.so.4",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libsdp.a", ["package=bluetooth", "dev"], False),
        (":" + name + "_stripped", "/usr/lib/libsdp.so.4", ["package=bluetooth", "lib"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libsdp.so.4.debug", ["package=bluetooth", "dbg"], False),
    ]
    for header in ['sdp.h']:
        files.append((header, "/usr/include/" + header, ["package=bluetooth", "dev"], False))
    for manual in ['sdp.3']:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = manual,
            output = name + "/" + manual + ".gz", arguments = ["-cn"],
            compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=bluetooth-man"],
            "//conditions:default": ["package=bluetooth-dev"]})
        files.append((":" + target, _manpath(manual), tags, True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    for original, alias in [('sdp.3', 'SDP_GET8.3'), ('sdp.3', 'SDP_GET16.3'), ('sdp.3', 'SDP_GET32.3'), ('sdp.3', 'SDP_GET64.3'), ('sdp.3', 'SDP_GET128.3'), ('sdp.3', 'SDP_PUT8.3'), ('sdp.3', 'SDP_PUT16.3'), ('sdp.3', 'SDP_PUT32.3'), ('sdp.3', 'SDP_PUT64.3'), ('sdp.3', 'SDP_PUT128.3'), ('sdp.3', 'sdp_open.3'), ('sdp.3', 'sdp_open_local.3'), ('sdp.3', 'sdp_close.3'), ('sdp.3', 'sdp_error.3'), ('sdp.3', 'sdp_search.3'), ('sdp.3', 'sdp_attr2desc.3'), ('sdp.3', 'sdp_uuid2desc.3'), ('sdp.3', 'sdp_register_service.3'), ('sdp.3', 'sdp_unregister_service.3'), ('sdp.3', 'sdp_change_service.3')]:
        target = name + "_alias_" + alias
        bsd_install_link(manual = True, name = target, destination = _manpath(alias), target = _manpath(original),
            kind = "hardlink", owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=bluetooth-man"],
                "//conditions:default": ["package=bluetooth-dev"]}))
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libsdp.so", target = "libsdp.so.4",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=bluetooth", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
