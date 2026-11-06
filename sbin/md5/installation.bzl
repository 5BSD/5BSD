# SPDX-License-Identifier: BSD-2-Clause
"""Digest installation inventory owned by the native build graph."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")

ALIASES = [
    "md5sum", "rmd160", "rmd160sum", "sha1", "sha1sum", "sha224", "sha224sum",
    "sha256", "sha256sum", "sha384", "sha384sum", "sha512", "sha512sum",
    "sha512t224", "sha512t224sum", "sha512t256", "sha512t256sum",
    "skein256", "skein256sum", "skein512", "skein512sum", "skein1024", "skein1024sum",
]

def digest_installation(name):
    native.filegroup(name = name + "_debug", srcs = [":debug"], output_group = "debug_files")
    man_tags = select({
        "//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"],
        "//conditions:default": ["package=runtime"],
    })
    files = [
        ("binary", ":stripped", "/sbin/md5", "0555", ["package=runtime"], False),
        ("symbols", ":" + name + "_debug", "/usr/lib/debug/sbin/md5.debug", "0444", ["dbg", "package=runtime"], False),
        ("manual", ":manual", "/usr/share/man/man1/md5.1.gz", "0444", man_tags, True),
    ]
    entries = []
    for suffix, source, destination, mode, tags, is_manual in files:
        target = name + "_" + suffix
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = mode, install_tags = tags)
        entries.append(":" + target)
    for alias in ALIASES:
        for suffix, destination, source, mode, tags, is_manual in [
            ("bin", "/sbin/" + alias, "/sbin/md5", "0555", ["package=runtime"], False),
            ("man", "/usr/share/man/man1/" + alias + ".1.gz", "/usr/share/man/man1/md5.1.gz", "0444", man_tags, True),
        ]:
            target = name + "_" + suffix + "_" + alias
            bsd_install_link(manual = is_manual, name = target, destination = destination, target = source,
                kind = "hardlink", owner = "root", group = "wheel", mode = mode, install_tags = tags)
            entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
