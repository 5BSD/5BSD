# SPDX-License-Identifier: BSD-2-Clause
# What Make installs for the PRIVATELIB protobuf-lite (lib/protobuf/libprotobuf-lite/Makefile): archive,
# shared object and its development link, separate debug file, the private
# headers (INCSGROUPS, Make order) and licences (FILESGROUPS).
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

HEADERS = [
]

LICENSES = [
]

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":protobuf_lite_shared",
        binary_name = name + "/libprivateprotobuf-lite.so.29", debug_name = name + "/libprivateprotobuf-lite.so.29.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libprivateprotobuf-lite.so.29",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [(source, destination, ["package=protobuf", "dev"]) for source, destination in HEADERS]
    files += [
        (":static_archive", "/usr/lib/libprivateprotobuf-lite.a", ["package=protobuf", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libprivateprotobuf-lite.so.29", ["package=protobuf"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libprivateprotobuf-lite.so.29.debug", ["package=protobuf", "dbg"]),
    ]
    files += [(source, destination, ["package=" + package]) for source, destination, package in LICENSES]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libprivateprotobuf-lite.so", target = "libprivateprotobuf-lite.so.29",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=protobuf", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
