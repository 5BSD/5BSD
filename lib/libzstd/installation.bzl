# SPDX-License-Identifier: BSD-2-Clause
"""Private base zstd library installation inventory."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_directory", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
def zstd_library_installation(name):
    native.filegroup(name = "debug_artifact", srcs = [":debug"], output_group = "debug_files")
    entries = []
    for suffix, destination in [("debug_usr", "/usr/lib/debug/usr"), ("debug_lib", "/usr/lib/debug/usr/lib")]:
        entry = name + "_" + suffix
        bsd_install_directory(name = entry, destination = destination, owner = "root", group = "wheel", mode = "0755",
            install_tags = ["package=zstd", "dbg"])
        entries.append(":" + entry)
    for suffix, source, destination, tags in [
        ("archive", ":static_archive", "/usr/lib/libprivatezstd.a", ["package=zstd", "dev"]),
        ("shared", ":stripped", "/usr/lib/libprivatezstd.so.5", ["package=zstd", "lib"]),
        ("symbols", ":debug_artifact", "/usr/lib/debug/usr/lib/libprivatezstd.so.5.debug", ["package=zstd", "dbg"]),
        ("header", "//sys/contrib/zstd:lib/zstd.h", "/usr/include/private/zstd/zstd.h", ["package=zstd", "dev"]),
        ("errors_header", "//sys/contrib/zstd:lib/zstd_errors.h", "/usr/include/private/zstd/zstd_errors.h", ["package=zstd", "dev"]),
    ]:
        entry = name + "_" + suffix
        bsd_install_file(name = entry, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + entry)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libprivatezstd.so",
        target = "libprivatezstd.so.5", kind = "symlink", owner = "root", group = "wheel",
        mode = "0755", install_tags = ["package=zstd", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
