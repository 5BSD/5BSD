# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned manual groups with Make-compatible packaging and hardlinks."""
load(":bsd_install.bzl", "bsd_compress", "bsd_install_file", "bsd_install_link")

def _path(page):
    if page.startswith("/") or ".." in page.split("/") or "." not in page:
        fail("manual name must be a relative name with a section suffix")
    section = page.rsplit(".", 1)[1]
    return "/usr/share/man/man" + section + "/" + page

def manual_entries(name, pages, package = "utilities", aliases = [], sources = {},
                   split = True, subpackage = ""):
    """Return typed entries for a final manifest; aliases may span groups.

    An explicit Make <group>PACKAGE ignores the group subpackage. Such callers
    pass split=False. Other groups replace their suffix with -man when split.
    """
    tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=" + package + "-man"],
        "//conditions:default": ["package=" + package + subpackage]}) if split else ["package=" + package]
    entries = []
    compressed = "//tools/build/bazel/config:mancompress_enabled"
    if len(depset(pages).to_list()) != len(pages):
        fail("duplicate manual page")
    for index, page in enumerate(pages):
        item = name + "_page_" + str(index)
        source = sources.get(page, page)
        bsd_compress(name = item + "_gzip", src = source, output = item + "/" + page + ".gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        bsd_install_file(name = item, manual = True, src = select({compressed: ":" + item + "_gzip", "//conditions:default": source}),
            destination = select({compressed: _path(page) + ".gz", "//conditions:default": _path(page)}),
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + item)
    for index, (source, alias) in enumerate(aliases):
        item = name + "_alias_" + str(index)
        bsd_install_link(name = item, manual = True, destination = select({compressed: _path(alias) + ".gz", "//conditions:default": _path(alias)}),
            target = select({compressed: _path(source) + ".gz", "//conditions:default": _path(source)}),
            kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + item)
    return entries
