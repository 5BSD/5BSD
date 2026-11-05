# SPDX-License-Identifier: BSD-2-Clause
"""Installed LLVM/Clang private shared libraries (no installed static archive)."""
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")

load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

def compiler_shared_installation(name, library, major, binary, package = "clang"):
    soname = "libprivate" + library + ".so." + str(major)
    bsd_debug_split(name = name + "_debug", src = binary,
        binary_name = name + "/" + soname, debug_name = name + "/" + soname + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/" + soname,
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    bsd_install_file(name = name + "_library", src = ":" + name + "_stripped", destination = "/usr/lib/" + soname,
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=" + package])
    bsd_install_file(name = name + "_symbols_file", src = ":" + name + "_symbols", destination = "/usr/lib/debug/usr/lib/" + soname + ".debug",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=" + package, "dbg"])
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libprivate" + library + ".so", target = soname,
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=" + package, "dev"])
    bsd_install_manifest(name = name, entries = [":" + name + "_library", ":" + name + "_symbols_file", ":" + name + "_link"], visibility = ["//visibility:public"])


def compiler_shared_archive(name, package = "clang"):
    bsd_install_archive(name = name, manifests = [":install_manifest"],
        directories = {path: json.encode(dict(owner = "root", group = "wheel", mode = "0755",
            tags = ["package=" + package, "dbg"])) for path in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/lib"]},
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr",
            "//etc/mtree:BSD.include.dist": "/usr/include", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"],
        visibility = ["//lib/clang:__pkg__"],
    )
