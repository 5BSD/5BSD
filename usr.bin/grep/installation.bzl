# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
_ALIASES = ["zfgrep", "zegrep", "bzgrep", "bzegrep", "bzfgrep", "lzgrep", "lzegrep", "lzfgrep", "xzgrep", "xzegrep", "xzfgrep", "zstdgrep", "zstdegrep", "zstdfgrep"]
def script_installation(name):
    bsd_install_file(name = name + "_script", src = "zgrep.sh", destination = "/usr/bin/zgrep", owner = "root", group = "wheel", mode = "0555", install_tags = ["package=runtime"])
    bsd_compress(name = name + "_manual", src = "zgrep.1", output = name + "/zgrep.1.gz", arguments = ["-cn"],
        compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"], "//conditions:default": ["package=runtime"]})
    bsd_install_file(name = name + "_man", src = ":" + name + "_manual", destination = "/usr/share/man/man1/zgrep.1.gz", owner = "root", group = "wheel", mode = "0444", install_tags = tags)
    entries = [":" + name + "_script", ":" + name + "_man"]
    for alias in _ALIASES:
        for suffix, dest, target, mode, labels in [("_bin", "/usr/bin/" + alias, "/usr/bin/zgrep", "0555", ["package=runtime"]), ("_man", "/usr/share/man/man1/" + alias + ".1.gz", "/usr/share/man/man1/zgrep.1.gz", "0444", tags)]:
            label = name + "_" + alias + suffix
            bsd_install_link(name = label, destination = dest, target = target, kind = "hardlink", owner = "root", group = "wheel", mode = mode, install_tags = labels)
            entries.append(":" + label)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
