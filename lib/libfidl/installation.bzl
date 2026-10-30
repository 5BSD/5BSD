# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

load(":installation_headers.bzl", "FIDL_INSTALL_HEADERS")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":fidl_shared",
        binary_name = name + "/libfidl_bsd.so.1", debug_name = name + "/libfidl_bsd.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libfidl_bsd.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libfidl_bsd.a", ["package=libfidl", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libfidl_bsd.so.1", ["package=libfidl"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libfidl_bsd.so.1.debug", ["package=libfidl", "dbg"]),
    ]
    bsd_compress(name = name + "_manual", src = "libfidl_bsd.3",
        output = name + "/libfidl_bsd.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libfidl_bsd.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libfidl-man"], "//conditions:default": ["package=libfidl-dev"]})))
    for source, destination in FIDL_INSTALL_HEADERS:
        if source.startswith("contrib/fuchsia/"):
            label = "@fuchsia_runtime_src//:" + source.removeprefix("contrib/fuchsia/")
        elif source.startswith("lib/libfidl/"):
            label = source.removeprefix("lib/libfidl/")
        else:
            fail("unrecognized FIDL header owner: " + source)
        files.append((label, "/usr/include/" + destination, ["package=libfidl", "dev"]))
    files += [
        ("fidl.pc", "/usr/libdata/pkgconfig/fidl.pc", ["package=libfidl-dev"]),
        ("//lib/libfidl/tests:zx.fidl", "/usr/share/fidl/zx.fidl", ["package=libfidl-dev"]),
        ("@fuchsia_runtime_src//:LICENSE", "/usr/share/licenses/libfidl/LICENSE", ["package=libfidl"]),
        ("@fuchsia_runtime_src//:PATENTS", "/usr/share/licenses/libfidl/PATENTS", ["package=libfidl"]),
    ]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libfidl_bsd.so", target = "libfidl_bsd.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libfidl", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
