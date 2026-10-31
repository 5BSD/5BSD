# SPDX-License-Identifier: BSD-2-Clause
# What Make installs for the INTERNALLIB lib/protobuf/libupb: only its licences
# (FILESGROUPS); the archives stay in the object tree.
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")

LICENSES = [
    ("//contrib/protobuf:LICENSE", "/usr/share/licenses/upb/LICENSE", "utilities"),
    ("//contrib/protobuf:third_party/utf8_range/LICENSE", "/usr/share/licenses/upb/utf8_range/LICENSE", "utilities"),
]

def library_installation(name):
    entries = []
    for source, destination, package in LICENSES:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=" + package])
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
