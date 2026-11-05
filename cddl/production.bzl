# SPDX-License-Identifier: BSD-2-Clause
"""Compose existing CDDL producers without importing Make at build time."""
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")

def production_archives(archives):
    # The full original installed test hierarchy and other ABIs remain open.
    bsd_install_archive_set(name = "production_installation_archives", archives = archives,
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"] + select({
            "//tools/build/bazel/config:tests_enabled": ["@platforms//:incompatible"], "//conditions:default": []}),
        visibility = ["//visibility:public"])
