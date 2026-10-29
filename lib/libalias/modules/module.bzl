# SPDX-License-Identifier: BSD-2-Clause
"""Userland libalias protocol modules; kernel modules are separate targets."""
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_shared_library")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_archive")
def alias_module(name):
    cc_library(name = "objects", srcs = ["//sys/netinet/libalias:alias_" + name + ".c"],
        deps = ["//sys/netinet/libalias:headers"], linkstatic = True,
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"])
    bsd_component_archive(name = "static_archive", groups = [":objects"], visibility = ["//visibility:public"])
    cc_shared_library(name = "module", deps = [":objects"], shared_lib_name = "libalias_" + name + ".so",
        user_link_flags = ["-Wl,-soname,libalias_" + name + ".so", "-Wl,--fatal-warnings,--warn-shared-textrel"],
        visibility = ["//visibility:public"])
