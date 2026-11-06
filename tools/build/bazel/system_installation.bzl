# SPDX-License-Identifier: BSD-2-Clause
"""Compose declared native world and kernel pkgbase without staged tree discovery."""
load(":bsd_install_archive.bzl", "bsd_install_archive_set")
load(":bsd_install_payload_inventory.bzl", "bsd_install_payload_inventory")
load(":bsd_pkg_family.bzl", "bsd_pkg_family_set")
load(":bsd_world_package_inventory.bzl", "bsd_world_package_inventory")
load(":bsd_world_package_reconciliation.bzl", "bsd_world_package_reconciliation")
load(":bsd_world_pkg_create.bzl", "bsd_world_pkg_create")
load(":bsd_world_pkg_solver_test.bzl", "bsd_world_pkg_solver_test")
load(":world_installation.bzl", "world_construction_manifests")

def system_pkgbase(name, kernel_packages):
    """Combine one explicit kernel graph with the source-selected world graph."""
    bsd_pkg_family_set(name = name + "_families", families = ["//packages:world_family_manifests",
        kernel_packages + "_families"], visibility = ["//visibility:public"])
    bsd_install_archive_set(name = name + "_installation", archives = ["//:fresh_world_contributions",
        kernel_packages + "_installation", kernel_packages + "_world_modules"], visibility = ["//visibility:public"])
    native.filegroup(name = name + "_payloads", srcs = [":" + name + "_installation"],
        output_group = "payload", visibility = ["//visibility:public"])
    bsd_install_payload_inventory(name = name + "_payload_inventory", installation = ":" + name + "_installation",
        visibility = ["//visibility:public"])
    suffixes = ["dbg", "dev", "lib"] + select({"//tools/build/bazel/config:split_manpages_enabled": ["man"], "//conditions:default": []})
    bsd_world_package_inventory(name = name + "_inventory", archives = [":" + name + "_installation"],
        construction = world_construction_manifests(), suffix_tags = suffixes, visibility = ["//visibility:public"])
    bsd_world_package_reconciliation(name = name + "_reconciliation", inventory = ":" + name + "_inventory",
        families = ":" + name + "_families", visibility = ["//visibility:public"])
    bsd_world_pkg_create(name = name, families = ":" + name + "_families", archives = ":" + name + "_installation",
        inventory = ":" + name + "_inventory", reconciliation = ":" + name + "_reconciliation",
        abi_file = "//usr.bin/uname:uname", suffix_tags = suffixes, visibility = ["//visibility:public"])
    bsd_world_pkg_solver_test(name = name + "_solver_test", packages = ":" + name,
        families = ":" + name + "_families", abi_file = "//usr.bin/uname:uname", size = "large", timeout = "long",
        visibility = ["//visibility:public"])
