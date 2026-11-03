# SPDX-License-Identifier: BSD-2-Clause
"""Default private framework installation, owned by the Googletest package."""
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_directory", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")

def framework_installation(component, headers):
    soname = "libprivate" + component + ".so.0"
    bsd_debug_split(name = "library_debug", src = ":" + component + "_shared",
        binary_name = "installed/" + soname, debug_name = "installed/" + soname + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    native.filegroup(name = "library_symbols", srcs = [":library_debug"], output_group = "debug_files")
    bsd_strip_binary(name = "library_stripped", src = ":library_debug", output = "stripped/" + soname,
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    entries = []
    files = [(":static_archive", "/usr/lib/libprivate" + component + ".a", ["package=googletest", "dev"]),
        (":library_stripped", "/usr/lib/" + soname, ["package=googletest"]),
        (":library_symbols", "/usr/lib/debug/usr/lib/" + soname + ".debug", ["package=googletest", "dbg"])]
    files += [(source, "/usr/include/private/" + component + "/" + destination,
        ["package=googletest", "dev"]) for destination, source in headers.items()]
    for index, (source, destination, tags) in enumerate(files):
        target = "install_file_" + str(index)
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = "install_link", destination = "/usr/lib/libprivate" + component + ".so",
        target = soname, kind = "symlink", owner = "root", group = "wheel", mode = "0755",
        install_tags = ["package=googletest", "dev"])
    # bsd.lib.mk records these debug package directories during component install.
    for index, directory in enumerate(["/usr/lib/debug/usr", "/usr/lib/debug/usr/lib"]):
        target = "install_debug_directory_" + str(index)
        bsd_install_directory(name = target, destination = directory,
            owner = "root", group = "wheel", mode = "0755", install_tags = ["package=googletest", "dbg"])
        entries.append(":" + target)
    bsd_install_manifest(name = "install_manifest", entries = entries + [":install_link"],
        visibility = ["//visibility:public"])
