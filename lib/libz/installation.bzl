# SPDX-License-Identifier: BSD-2-Clause
"""Native zlib installation inventory."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_compress", "bsd_install_directory", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")

def zlib_installation(name):
    native.filegroup(name = name + "_archive", srcs = [":static_archive"])
    native.filegroup(name = name + "_debug", srcs = [":debug"], output_group = "debug_files")
    bsd_install_directory(name = name + "_debug_lib_dir", destination = "/usr/lib/debug/lib",
        owner = "root", group = "wheel", mode = "0755", install_tags = ["package=zlib", "dbg"])
    entries = [":" + name + "_debug_lib_dir"]
    files = [
        ("archive", ":" + name + "_archive", "/usr/lib/libz.a", ["package=zlib", "dev"], False),
        ("shared", ":stripped", "/lib/libz.so.6", ["package=zlib"], False),
        ("symbols", ":" + name + "_debug", "/usr/lib/debug/lib/libz.so.6.debug", ["package=zlib", "dbg"], False),
        ("pkgconfig", ":pkgconfig", "/usr/libdata/pkgconfig/zlib.pc", ["package=zlib", "dev"], False),
        ("zlib_h", "//sys/contrib/zlib:zlib.h", "/usr/include/zlib.h", ["package=zlib", "dev"], False),
        ("zconf_h", "//sys/contrib/zlib:zconf.h", "/usr/include/zconf.h", ["package=zlib", "dev"], False),
    ]
    man_tags = select({
        "//tools/build/bazel/config:split_manpages_enabled": ["package=zlib-man"],
        "//conditions:default": ["package=zlib-dev"],
    })
    for manual, source in [("zlib", "//sys/contrib/zlib:zlib.3"), ("zopen", "zopen.3")]:
        compressed = name + "_compressed_" + manual
        bsd_compress(name = compressed, src = source, output = manual + ".3.gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append(("manual_" + manual, ":" + compressed, "/usr/share/man/man3/" + manual + ".3.gz", man_tags, True))
    for suffix, source, destination, tags, is_manual in files:
        entry = name + "_file_" + suffix
        bsd_install_file(manual = is_manual, name = entry, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + entry)
    for suffix, destination, target, kind, mode, tags, is_manual in [
        ("shared", "/usr/lib/libz.so", "../../lib/libz.so.6", "symlink", "0755", ["package=zlib", "dev"], False),
        ("manual", "/usr/share/man/man3/zdopen.3.gz", "/usr/share/man/man3/zopen.3.gz", "hardlink", "0444", man_tags, True),
    ]:
        entry = name + "_link_" + suffix
        bsd_install_link(manual = is_manual, name = entry, destination = destination, target = target,
            kind = kind, owner = "root", group = "wheel", mode = mode, install_tags = tags)
        entries.append(":" + entry)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
