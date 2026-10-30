# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load(":installation_data.bzl", "PROFILES", "ALIASES")

def compatibility_installation(name):
    directory = "/usr/share/zfs/compatibility.d/"
    entries = []
    for profile in PROFILES:
        target = name + "_profile_" + profile
        bsd_install_file(name = target,
            src = "//sys/contrib/openzfs:cmd/zpool/compatibility.d/" + profile,
            destination = directory + profile, owner = "root", group = "wheel",
            mode = "0444", install_tags = ["package=zfs"])
        entries.append(":" + target)
    for source, alias in ALIASES:
        target = name + "_alias_" + alias
        bsd_install_link(name = target, destination = directory + alias,
            target = directory + source, kind = "hardlink", owner = "root",
            group = "wheel", mode = "0444", install_tags = ["package=zfs"])
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
