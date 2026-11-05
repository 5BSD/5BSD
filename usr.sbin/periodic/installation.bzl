# SPDX-License-Identifier: BSD-2-Clause
"""Periodic configuration groups; filenames and option selection belong to BUILD."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")

def periodic_configuration(name, files, directory, package = "periodic", mode = "0755"):
    entries = []
    for source in files:
        target = name + "_" + source
        bsd_install_file(
            name = target,
            src = source,
            destination = directory + "/" + source,
            owner = "root",
            group = "wheel",
            mode = mode,
            install_tags = ["package=" + package, "config"],
        )
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries)
