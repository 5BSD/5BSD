# SPDX-License-Identifier: BSD-2-Clause
"""ZFS daily periodic payload; other periodic groups migrate independently."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")

ZFS_SERVICES = ["223.backup-zfs", "404.status-zfs", "800.scrub-zfs", "801.trim-zfs"]

def zfs_installation(name):
    entries = []
    for service in ZFS_SERVICES:
        target = name + "_" + service
        bsd_install_file(name = target, src = service,
            destination = "/etc/periodic/daily/" + service, owner = "root", group = "wheel",
            mode = "0755", install_tags = ["package=zfs", "config"])
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
