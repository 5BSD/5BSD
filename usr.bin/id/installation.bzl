# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")

def identity_aliases(name, base_entries):
    entries = list(base_entries)
    tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"], "//conditions:default": ["package=runtime"]})
    for alias in ["groups", "whoami"]:
        target = name + "_" + alias
        bsd_install_link(name = target, destination = "/usr/bin/" + alias,
            target = "/usr/bin/id", kind = "hardlink", owner = "root", group = "wheel",
            mode = "0555", install_tags = ["package=runtime"])
        bsd_compress(name = target + "_compressed", src = alias + ".1", output = target + ".1.gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        bsd_install_file(manual = True, name = target + "_manual", src = ":" + target + "_compressed",
            destination = "/usr/share/man/man1/" + alias + ".1.gz", owner = "root", group = "wheel",
            mode = "0444", install_tags = tags)
        entries += [":" + target, ":" + target + "_manual"]
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
