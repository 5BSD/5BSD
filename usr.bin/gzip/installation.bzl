# SPDX-License-Identifier: BSD-2-Clause
"""Gzip installation inventory, maintained independently of Make evaluation."""
load("//tools/build/bazel:bsd_base_install.bzl", "bsd_program_install")
load("//tools/build/bazel:bsd_install.bzl", "bsd_compress", "bsd_install_file", "bsd_install_link")

SCRIPTS = ["gzexe", "zdiff", "zforce", "zmore", "znew"]
MANUALS = ["gzip", "gzexe", "zdiff", "zforce", "zmore", "znew"]
PROGRAM_LINKS = {"gunzip": "gzip", "gzcat": "gzip", "zcat": "gzip", "xzdiff": "zdiff", "zcmp": "zdiff"}
MANUAL_LINKS = dict(PROGRAM_LINKS, zless = "zmore")

def gzip_installation(name):
    entries = []
    man_tags = select({
        "//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"],
        "//conditions:default": ["package=utilities"],
    })
    for script in SCRIPTS:
        entry = name + "_script_" + script
        bsd_install_file(name = entry, src = script, destination = "/usr/bin/" + script,
            owner = "root", group = "wheel", mode = "0555", install_tags = ["package=utilities"])
        entries.append(":" + entry)
    for manual in MANUALS:
        compressed = name + "_compressed_" + manual
        bsd_compress(name = compressed, src = manual + ".1", output = manual + ".1.gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        entry = name + "_manual_" + manual
        bsd_install_file(name = entry, src = ":" + compressed,
            destination = "/usr/share/man/man1/" + manual + ".1.gz",
            owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + entry)
    for kind, links, prefix, suffix, mode, tags in [
        ("bin", PROGRAM_LINKS, "/usr/bin/", "", "0555", ["package=utilities"]),
        ("man", MANUAL_LINKS, "/usr/share/man/man1/", ".1.gz", "0444", man_tags),
    ]:
        for alias, original in links.items():
            entry = name + "_" + kind + "_link_" + alias
            bsd_install_link(name = entry, destination = prefix + alias + suffix,
                target = prefix + original + suffix, kind = "hardlink",
                owner = "root", group = "wheel", mode = mode, install_tags = tags)
            entries.append(":" + entry)
    bsd_program_install(name = name, binary = ":stripped", debug = ":debug",
        destination = "/usr/bin/gzip", package = "utilities", extra_entries = entries,
        visibility = ["//visibility:public"])
