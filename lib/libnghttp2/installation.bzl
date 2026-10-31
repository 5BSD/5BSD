# SPDX-License-Identifier: BSD-2-Clause
# What Make installs for the PRIVATELIB nghttp2 (lib/libnghttp2/Makefile): archive,
# shared object and its development link, separate debug file, the private
# headers (INCSGROUPS, Make order) and licences (FILESGROUPS).
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

HEADERS = [
    ("//contrib/nghttp2:lib/includes/nghttp2/nghttp2.h", "/usr/include/private/nghttp2/nghttp2.h"),
    ("nghttp2/nghttp2ver.h", "/usr/include/private/nghttp2/nghttp2ver.h"),
]

LICENSES = [
    ("//contrib/nghttp2:COPYING", "/usr/share/licenses/nghttp2/COPYING", "libnghttp2"),
]

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":nghttp2_shared",
        binary_name = name + "/libprivatenghttp2.so.14", debug_name = name + "/libprivatenghttp2.so.14.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libprivatenghttp2.so.14",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [(source, destination, ["package=libnghttp2", "dev"]) for source, destination in HEADERS]
    files += [
        (":static_archive", "/usr/lib/libprivatenghttp2.a", ["package=libnghttp2", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libprivatenghttp2.so.14", ["package=libnghttp2"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libprivatenghttp2.so.14.debug", ["package=libnghttp2", "dbg"]),
    ]
    files += [(source, destination, ["package=" + package]) for source, destination, package in LICENSES]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libprivatenghttp2.so", target = "libprivatenghttp2.so.14",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libnghttp2", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
