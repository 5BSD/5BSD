# SPDX-License-Identifier: BSD-2-Clause
"""Libbsdxml component inventory within the runtime package family."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_directory", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
def bsdxml_installation(name):
    native.filegroup(name = "archive", srcs = [":static_archive"])
    native.filegroup(name = "debug_file", srcs = [":debug"], output_group = "debug_files")
    native.filegroup(name = "public_header", srcs = [":generated_headers"], output_group = "public_header")
    native.filegroup(name = "external_header", srcs = [":generated_headers"], output_group = "external_header")
    bsd_install_directory(name = name + "_debug_lib_dir", destination = "/usr/lib/debug/lib",
        owner = "root", group = "wheel", mode = "0755", install_tags = ["package=runtime", "dbg"])
    entries = [":" + name + "_debug_lib_dir"]
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"],
        "//conditions:default": ["package=runtime-dev"]})
    for suffix, source, destination, tags, is_manual in [
        ("archive", ":archive", "/usr/lib/libbsdxml.a", ["package=runtime", "dev"], False),
        ("shared", ":stripped", "/lib/libbsdxml.so.4", ["package=runtime"], False),
        ("symbols", ":debug_file", "/usr/lib/debug/lib/libbsdxml.so.4.debug", ["package=runtime", "dbg"], False),
        ("public", ":public_header", "/usr/include/bsdxml.h", ["package=runtime", "dev"], False),
        ("external", ":external_header", "/usr/include/bsdxml_external.h", ["package=runtime", "dev"], False),
        ("manual", ":manual", "/usr/share/man/man3/libbsdxml.3.gz", man_tags, True),
    ]:
        entry = name + "_" + suffix
        bsd_install_file(manual = is_manual, name = entry, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + entry)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libbsdxml.so",
        target = "../../lib/libbsdxml.so.4", kind = "symlink", owner = "root", group = "wheel",
        mode = "0755", install_tags = ["package=runtime", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
