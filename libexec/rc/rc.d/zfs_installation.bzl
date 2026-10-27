# SPDX-License-Identifier: BSD-2-Clause
"""ZFS rc.d package payload; other rc groups migrate independently."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")

ZFS_SERVICES = ["zfs", "zfsbe", "zfsd", "zfskeys", "zpool", "zpoolreguid", "zpoolupgrade", "zvol"]

def zfs_installation(name):
    entries = []
    for service in ZFS_SERVICES:
        target = name + "_" + service
        bsd_install_file(name = target, src = service,
            destination = "/etc/rc.d/" + service, owner = "root", group = "wheel",
            mode = "0555", install_tags = ["package=zfs", "config"])
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
