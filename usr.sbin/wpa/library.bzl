# SPDX-License-Identifier: BSD-2-Clause
"""WPA INTERNALLIB policy using ordinary rules_cc source/object ownership."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_archive")
load("//usr.sbin/wpa:common.bzl", "PLATFORM", "compiler_flags", "crypto_flags", "inc_flags")

_VISIBILITY = ["//usr.sbin/wpa:__subpackages__"]

def wpa_private_library(name, srcs, headers, copts = []):
    """Compile both real Make variants; archive only each group's own objects."""
    for suffix in ["", "_pie"]:
        cc_library(
            name = name + suffix,
            srcs = srcs,
            deps = headers,
            copts = (["-fpie", "-DPIC"] if suffix else []) + inc_flags() +
                    crypto_flags() + copts + compiler_flags(),
            linkstatic = True,
            target_compatible_with = PLATFORM,
            visibility = _VISIBILITY,
        )
    bsd_component_archive(
        name = "static_archive",
        groups = [":" + name],
        target_compatible_with = PLATFORM,
        visibility = _VISIBILITY,
    )
    bsd_component_archive(
        name = "pie_archive",
        groups = [":" + name + "_pie"],
        target_compatible_with = PLATFORM,
        visibility = _VISIBILITY,
    )
