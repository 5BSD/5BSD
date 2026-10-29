# SPDX-License-Identifier: BSD-2-Clause
"""Clang driver installation, including its BSD aliases and CC script."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")

def clang_installation(binary):
    """Install an explicitly supplied system-link compiler, never a test wrapper."""
    bsd_install_file(name = "cc_script", src = "CC.sh", destination = "/usr/bin/CC",
        owner = "root", group = "wheel", mode = "0555", install_tags = ["package=clang"])
    utility_installation(name = "install_manifest", program = "clang", binary = binary,
        manual = "clang.1", package = "clang", bindir = "/usr/bin", man_section = "1",
        aliases = ["clang++", "clang-cpp", "cc", "c++", "cpp"],
        manual_aliases = ["CC"], extra_entries = [":cc_script"])
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"],
        mtree_specs = {
            "//etc/mtree:BSD.root.dist": "/",
            "//etc/mtree:BSD.usr.dist": "/usr",
            "//etc/mtree:BSD.include.dist": "/usr/include",
            "//etc/mtree:BSD.debug.dist": "/usr/lib",
        },
        passwd = "//etc:master.passwd", group = "//etc:group",
        mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python",
        python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"])
