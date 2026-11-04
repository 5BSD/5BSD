# SPDX-License-Identifier: BSD-2-Clause
"""Boot component data and manuals using declared source-owned inventories."""
load(":bsd_install.bzl", "bsd_compress", "bsd_install_file", "bsd_install_manifest")


def boot_data_installation(files = [], directory = "/boot", manuals = [], prefixes = [], manual_conditions = {}):
    entries = []
    for filename, source in files:
        name = "install_file_" + filename.replace(".", "_").replace("-", "_")
        bsd_install_file(name = name, src = source, destination = directory.rstrip("/") + "/" + filename,
            destination_prefixes = prefixes, owner = "root", group = "wheel", mode = "0444",
            install_tags = ["package=bootloader"])
        entries.append(":" + name)
    for manual in manuals:
        name = "manual_" + manual.replace(".", "_").replace("-", "_")
        section = manual.split(".")[-1]
        bsd_compress(name = name, src = manual, output = manual + ".gz", arguments = ["-cn"],
            compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        compressed = "//tools/build/bazel/config:mancompress_enabled"
        base = "/usr/share/man/man" + section + "/" + manual
        bsd_install_file(name = "install_" + name,
            src = select({compressed: ":" + name, "//conditions:default": manual}),
            destination = select({compressed: base + ".gz", "//conditions:default": base}),
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=bootloader-man"],
                "//conditions:default": ["package=bootloader"]}))
        setting = manual_conditions.get(manual, "//tools/build/bazel/config:man_enabled")
        entries += select({setting: [":install_" + name], "//conditions:default": []})
    bsd_install_manifest(name = "install_manifest", entries = entries, visibility = ["//visibility:public"])
