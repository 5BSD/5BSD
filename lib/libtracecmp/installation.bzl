# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

MANUAL_ALIASES = ["tracecmp_open", "tracecmp_stats", "tracecmp_dtrace_open"]

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":tracecmp_shared",
        binary_name = name + "/libtracecmp.so.1", debug_name = name + "/libtracecmp.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libtracecmp.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
                ("tracecmp.h", "/usr/include/tracecmp.h", ["package=libtracecmp", "dev"]),
        ("tracecmp_protocol.h", "/usr/include/tracecmp_protocol.h", ["package=libtracecmp", "dev"]),
        ("tracecmp_server.h", "/usr/include/tracecmp_server.h", ["package=libtracecmp", "dev"]),

        (":static_archive", "/usr/lib/libtracecmp.a", ["package=libtracecmp", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libtracecmp.so.1", ["package=libtracecmp"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libtracecmp.so.1.debug", ["package=libtracecmp", "dbg"]),
    ]
    bsd_compress(name = name + "_manual", src = "libtracecmp.3",
        output = name + "/libtracecmp.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libtracecmp.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libtracecmp-man"], "//conditions:default": ["package=libtracecmp-dev"]})))
    files.append(("tracecmp.fidl", "/usr/share/fidl/tracecmp.fidl", ["package=libtracecmp-dev"]))
    files += [("//contrib/fuchsia:" + n, "/usr/share/licenses/libtracecmp/fuchsia/" + n, ["package=libtracecmp"]) for n in ["LICENSE", "PATENTS"]]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libtracecmp.so", target = "libtracecmp.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libtracecmp", "dev"])
    for alias in MANUAL_ALIASES:
        target = name + "_manual_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/libtracecmp.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libtracecmp-man"], "//conditions:default": ["package=libtracecmp-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
