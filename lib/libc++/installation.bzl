# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load("@bazel_skylib//rules:expand_template.bzl", "expand_template")
load(":installation_data.bzl", "UPSTREAM_HEADERS", "LOCAL_HEADERS")

def libcxx_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":cxx_shared",
        binary_name = name + "/libc++.so.1", debug_name = name + "/libc++.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libc++.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    expand_template(name = name + "_linker_script", template = "libc++.ldscript", out = name + "/libc++.so",
        substitutions = {"@@SHLIB@@": "/lib/libc++.so.1", "@@LIBDIR@@": "/usr/lib"})
    files = [
        (":static_archive", "/usr/lib/libc++.a", ["package=clibs", "dev"]),
        (":" + name + "_stripped", "/lib/libc++.so.1", ["package=clibs"]),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libc++.so.1.debug", ["package=clibs", "dbg"]),
        (":" + name + "_linker_script", "/usr/lib/libc++.so", ["package=clibs", "dev"]),
    ]
    headers = [("//contrib/llvm-project/libcxx/include:" + h, h) for h in UPSTREAM_HEADERS] + LOCAL_HEADERS
    files += [(source, "/usr/include/c++/v1/" + path, ["package=clibs", "dev"]) for source, path in headers]
    entries = []
    for i, (source, destination, tags) in enumerate(files):
        target = name + "_file_" + str(i)
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
