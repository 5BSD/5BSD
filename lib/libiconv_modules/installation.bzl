# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")

def module_installation(name):
    library = "lib" + name + ".so.5"
    bsd_debug_split(name = name + "_debug", src = ":" + name,
        binary_name = "install/" + library, debug_name = "install/" + library + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug",
        output = "install/stripped/" + library,
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    bsd_install_file(name = name + "_install_binary", src = ":" + name + "_stripped",
        destination = "/usr/lib/i18n/" + library, owner = "root", group = "wheel", mode = "0444",
        install_tags = ["package=utilities"])
    bsd_install_file(name = name + "_install_debug", src = ":" + name + "_symbols",
        destination = "/usr/lib/debug/usr/lib/i18n/" + library + ".debug", owner = "root", group = "wheel", mode = "0444",
        install_tags = ["package=utilities", "dbg"])
    bsd_install_link(name = name + "_install_link", destination = "/usr/lib/i18n/lib" + name + ".so",
        target = library, kind = "symlink", owner = "root", group = "wheel", mode = "0755",
        install_tags = ["package=utilities", "dev"])
    bsd_install_manifest(name = name + "_install_manifest",
        entries = [":" + name + "_install_binary", ":" + name + "_install_debug", ":" + name + "_install_link"])
